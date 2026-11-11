using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

/// <summary>
/// Stand-in for StreamerCodecDetector.exe.
///
/// UU 会调用 "StreamerCodecDetector.exe --batch &lt;impl&gt; &lt;device&gt; &lt;adapter&gt;"，
/// 子进程在 stdout 上输出若干 RESULT 行，最后一行是 BATCH_DONE。
/// 这个替身做三件事：
///   1. 先把请求转发给原版（StreamerCodecDetector.orig.exe），保留它的真实结论；
///   2. 对 DXVA11（impl=32）用基线表补全缺失项，合并时取两者中能力更强的那个；
///   3. 无论如何都以退出码 0 结束，并写出完整的 RESULT 行与 BATCH_DONE。
///
/// 子进程放在 Job 对象里，替身被 UU 结束时原版会一起被回收，不会留孤儿进程。
/// </summary>
internal static class DetectorShim
{
    // RESULT,<video_codec>,<chroma_sampling>,<bit_depth>,<width>,<height>,<supported>
    private static readonly string[,] Matrix =
    {
        // codec, chroma, depth, width, height, supported
        { "1", "1", "8",  "3840", "2160", "1" },
        { "1", "1", "10", "0",    "0",    "0" },
        { "1", "3", "8",  "0",    "0",    "0" },
        { "1", "3", "10", "0",    "0",    "0" },
        { "2", "1", "8",  "3840", "2160", "1" },
        { "2", "1", "10", "3840", "2160", "1" },
        { "2", "3", "8",  "0",    "0",    "0" },
        { "2", "3", "10", "0",    "0",    "0" }
    };

    // 只有 DXVA11 走基线表补全。其余 impl（NvDec / AMF / oneVPL / MediaCodec ...）
    // 只转发原版结论，原版拿不到结果时按"全不支持"处理。
    private const int HwProbeImpl = 32;

    private const int DefaultTimeoutMs = 2500;
    private const long MaxLogBytes = 256 * 1024;

    private static int Main(string[] args)
    {
        string self = System.Reflection.Assembly.GetExecutingAssembly().Location;
        string dir = Path.GetDirectoryName(self);
        string logPath = Path.Combine(Path.GetTempPath(), "uu_detector_shim.log");

        if (args.Length < 4 || !string.Equals(args[0], "--batch", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine("Usage: StreamerCodecDetector --batch <impl> <device> <adapter>");
            Console.Out.Flush();
            Log(logPath, "BADARGS " + Join(args));
            return 1;
        }

        int impl = -1;
        int.TryParse(args[1], out impl);

        string orig = Environment.GetEnvironmentVariable("UUDET_ORIG");
        if (string.IsNullOrEmpty(orig)) orig = Path.Combine(dir, "StreamerCodecDetector.orig.exe");

        int timeoutMs = DefaultTimeoutMs;
        int parsed;
        string tmo = Environment.GetEnvironmentVariable("UUDET_TIMEOUT_MS");
        if (!string.IsNullOrEmpty(tmo) && int.TryParse(tmo, out parsed) && parsed > 0) timeoutMs = parsed;

        Log(logPath, "ENTER impl=" + impl + " device=" + args[2] + " adapter=" + args[3]);

        string childOut;
        bool childDone = RunChild(orig, dir, args, timeoutMs, out childOut);

        if (impl == HwProbeImpl)
        {
            Dictionary<string, string> child = ParseResults(childOut);
            int nz = 0;
            for (int i = 0; i < Matrix.GetLength(0); i++)
            {
                string key = Matrix[i, 0] + "," + Matrix[i, 1] + "," + Matrix[i, 2];
                string line;
                child.TryGetValue(key, out line);

                // 基线表只补"缺"：原版说不支持、或者分辨率更低时才用基线值。
                string floor = FloorLine(i);
                if (IsSupported(floor) && (!IsSupported(line) || Resolution(line) < Resolution(floor)))
                    line = floor;

                if (line == null) line = ZeroLine(i);
                if (IsSupported(line)) nz++;
                Console.WriteLine(line);
            }
            Console.WriteLine("BATCH_DONE");
            Console.Out.Flush();
            Log(logPath, "impl=" + impl + " hw childDone=" + childDone + " nonzero=" + nz);
            return 0;
        }

        if (childDone && childOut.IndexOf("BATCH_DONE", StringComparison.Ordinal) >= 0)
        {
            Console.Write(childOut);
            Console.Out.Flush();
            Log(logPath, "impl=" + impl + " verbatim " + childOut.Length + " chars");
            return 0;
        }

        for (int i = 0; i < Matrix.GetLength(0); i++) Console.WriteLine(ZeroLine(i));
        Console.WriteLine("BATCH_DONE");
        Console.Out.Flush();
        Log(logPath, "impl=" + impl + " childDone=" + childDone + " -> zeros");
        return 0;
    }

    private static string FloorLine(int i)
    {
        return "RESULT," + Matrix[i, 0] + "," + Matrix[i, 1] + "," + Matrix[i, 2] + "," +
               Matrix[i, 3] + "," + Matrix[i, 4] + "," + Matrix[i, 5];
    }

    private static string ZeroLine(int i)
    {
        return "RESULT," + Matrix[i, 0] + "," + Matrix[i, 1] + "," + Matrix[i, 2] + ",0,0,0";
    }

    private static bool IsSupported(string line)
    {
        if (string.IsNullOrEmpty(line)) return false;
        string[] p = line.Split(',');
        if (p.Length < 7) return false;
        return p[6].Trim() != "0";
    }

    private static long Resolution(string line)
    {
        if (line == null) return 0;
        string[] p = line.Split(',');
        if (p.Length < 6) return 0;
        long w = 0;
        long h = 0;
        long.TryParse(p[4], out w);
        long.TryParse(p[5], out h);
        return w * h;
    }

    private static Dictionary<string, string> ParseResults(string text)
    {
        Dictionary<string, string> map = new Dictionary<string, string>();
        if (string.IsNullOrEmpty(text)) return map;
        string[] lines = text.Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            string l = lines[i].Trim();
            if (!l.StartsWith("RESULT,", StringComparison.Ordinal)) continue;
            string[] p = l.Split(',');
            if (p.Length < 7) continue;
            map[p[1] + "," + p[2] + "," + p[3]] = l;
        }
        return map;
    }

    // 返回 true 表示子进程自己正常退出
    private static bool RunChild(string orig, string dir, string[] args, int timeoutMs, out string output)
    {
        output = "";
        if (!File.Exists(orig)) return false;

        IntPtr job = CreateKillOnCloseJob();
        StringBuilder sb = new StringBuilder();
        bool finished = false;
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = orig;
            psi.Arguments = Join(args);
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.CreateNoWindow = true;
            psi.WorkingDirectory = dir;

            Process p = new Process();
            p.StartInfo = psi;
            p.OutputDataReceived += delegate(object s, DataReceivedEventArgs e)
            {
                if (e.Data != null) sb.AppendLine(e.Data);
            };
            p.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e) { };
            p.Start();

            if (job != IntPtr.Zero)
            {
                try { AssignProcessToJobObject(job, p.Handle); }
                catch { }
            }

            p.BeginOutputReadLine();
            p.BeginErrorReadLine();


            finished = p.WaitForExit(timeoutMs);
            if (finished)
            {
                p.WaitForExit(); // 让异步读取把缓冲区刷完
            }
            else
            {
                try { p.Kill(); } catch { }
                try { p.WaitForExit(1500); } catch { }
            }
        }
        catch
        {
            finished = false;
        }
        finally
        {
            if (job != IntPtr.Zero) CloseHandle(job);
        }
        output = sb.ToString();
        return finished;
    }

    private static string Join(string[] args)
    {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < args.Length; i++)
        {
            if (i > 0) b.Append(' ');
            string a = args[i];
            if (a.IndexOf(' ') >= 0 || a.IndexOf('"') >= 0)
                b.Append('"').Append(a.Replace("\"", "\\\"")).Append('"');
            else
                b.Append(a);
        }
        return b.ToString();
    }

    private static void Log(string path, string msg)
    {
        try
        {
            FileInfo fi = new FileInfo(path);
            if (fi.Exists && fi.Length > MaxLogBytes) File.Delete(path);
            File.AppendAllText(path,
                DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + " " + msg + Environment.NewLine,
                Encoding.UTF8);
        }
        catch { }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    private const int JobObjectExtendedLimitInformation = 9;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr hJob, int infoClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInfo, int cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private static IntPtr CreateKillOnCloseJob()
    {
        try
        {
            IntPtr job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero) return IntPtr.Zero;
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            int len = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref info, len))
            {
                CloseHandle(job);
                return IntPtr.Zero;
            }
            return job;
        }
        catch { return IntPtr.Zero; }
    }
}
