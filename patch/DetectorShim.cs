using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
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

    private static int Main(string[] args)
    {
        string self = System.Reflection.Assembly.GetExecutingAssembly().Location;
        string dir = Path.GetDirectoryName(self);
        string logPath = Path.Combine(Path.GetTempPath(), "uu_detector_shim.log");

        if (args.Length < 4 || !string.Equals(args[0], "--batch", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine("Usage: StreamerCodecDetector --batch <impl> <device_id> <adapter_id>");
            Console.Out.Flush();
            Log(logPath, "BADARGS " + Join(args));
            return 1;
        }

        int impl = -1;
        int deviceId = -1;
        int.TryParse(args[1], out impl);
        int.TryParse(args[2], out deviceId);
        Log(logPath, "ENTER impl=" + impl + " dev=" + deviceId + " argc=" + args.Length);

        string orig = Environment.GetEnvironmentVariable("UUDET_ORIG");
        if (string.IsNullOrEmpty(orig)) orig = Path.Combine(dir, "StreamerCodecDetector.orig.exe");

        int timeoutMs = 3000;
        int parsed;
        string tmo = Environment.GetEnvironmentVariable("UUDET_TIMEOUT_MS");
        if (!string.IsNullOrEmpty(tmo) && int.TryParse(tmo, out parsed) && parsed > 0) timeoutMs = parsed;

        string childOut;
        bool childDone = RunChild(orig, dir, args, timeoutMs, out childOut);

        bool isHwProbe = (impl == 32);

        if (isHwProbe)
        {
            Dictionary<string, string> child = ParseResults(childOut);
            int nz = 0;
            for (int i = 0; i < Matrix.GetLength(0); i++)
            {
                string key = Matrix[i, 0] + "," + Matrix[i, 1] + "," + Matrix[i, 2];
                string line = null;
                string c;
                if (child.TryGetValue(key, out c))
                {
                    line = c;
                }
                if (!IsSupported(line) && IsSupported(FloorLine(i)))
                {
                    line = FloorLine(i);
                }
                if (line == null) line = ZeroLine(i);
                if (IsSupported(line)) nz++;
                Console.WriteLine(line);
            }
            Console.WriteLine("BATCH_DONE");
            Console.Out.Flush();
            Log(logPath, "impl=" + impl + " dev=" + deviceId + " hw childDone=" + childDone + " nonzero=" + nz);
            return 0;
        }

        if (childDone && childOut.IndexOf("BATCH_DONE", StringComparison.Ordinal) >= 0)
        {
            Console.Write(childOut);
            Console.Out.Flush();
            Log(logPath, "impl=" + impl + " dev=" + deviceId + " verbatim " + childOut.Length + " chars");
            return 0;
        }

        for (int i = 0; i < Matrix.GetLength(0); i++) Console.WriteLine(ZeroLine(i));
        Console.WriteLine("BATCH_DONE");
        Console.Out.Flush();
        Log(logPath, "impl=" + impl + " dev=" + deviceId + " childDone=" + childDone + " -> zeros");
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

    // Returns true only when the child exited on its own
    private static bool RunChild(string orig, string dir, string[] args, int timeoutMs, out string output)
    {
        output = "";
        if (!File.Exists(orig)) return false;
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
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();

            finished = p.WaitForExit(timeoutMs);
            if (finished)
            {
                p.WaitForExit(); // let async readers flush
            }
            else
            {
                try { p.Kill(); } catch { }
                try { p.WaitForExit(2000); } catch { }
            }
        }
        catch
        {
            finished = false;
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
            File.AppendAllText(path,
                DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + " " + msg + Environment.NewLine,
                Encoding.UTF8);
        }
        catch { }
    }
}
