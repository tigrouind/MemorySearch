using System.Diagnostics;
using System.Text;
using System.Runtime.InteropServices;

class MemoryScanner
{
	#region Process

	const int PROCESS_QUERY_INFORMATION = 0x0400;
	const int PROCESS_VM_READ = 0x0010;

	const uint MEM_COMMIT = 0x1000;
	const uint PAGE_READWRITE = 0x04;

	[DllImport("kernel32.dll")]
	static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

	[DllImport("kernel32.dll", SetLastError = true)]
	static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

	[DllImport("kernel32.dll", SetLastError = true)]
	static extern bool CloseHandle(IntPtr hHandle);

	[DllImport("kernel32.dll")]
	static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
		out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

	[StructLayout(LayoutKind.Sequential)]
	struct MEMORY_BASIC_INFORMATION
	{
		public IntPtr BaseAddress;
		public IntPtr AllocationBase;
		public uint AllocationProtect;
		public IntPtr RegionSize;
		public uint State;
		public uint Protect;
		public uint Type;
	}

	#endregion

	static void Main()
	{
		const string searchString = "DOOM"; // Search target
		const int charBefore = 5;
		const int charAfter = 30;

		var searchBytes = Encoding.ASCII.GetBytes(searchString);

		var allProcesses = Process.GetProcesses()
			.Where(x => x.ProcessName == "chrome")
			.OrderBy(x => x.ProcessName)
			.ToArray();

		foreach (var result in allProcesses
			.AsParallel()
			.AsOrdered()
			.WithMergeOptions(ParallelMergeOptions.NotBuffered)
			.SelectMany(process => GetLines(searchBytes, process), (x, y) => (Process: x, Text: y)))
		{
			Console.WriteLine($"[{result.Process.ProcessName} {result.Process.Id}] {result.Text}");
		}

		Console.WriteLine("Done.");
		Console.ReadLine();

		static IEnumerable<string> GetLines(byte[] searchBytes, Process process)
		{
			var results = new HashSet<string>();
			var buffer = new byte[1024 * 1024 * 4];

			foreach (var text in SearchProcess(process, searchBytes, buffer))
			{
				if (results.Add(text))
				{
					yield return text;
				}
			}
		}

		static IEnumerable<string> SearchProcess(Process process, byte[] searchBytes, byte[] buffer)
		{
			IntPtr hProc = IntPtr.Zero;

			hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process.Id);
			if (hProc == IntPtr.Zero)
			{
				yield break;
			}

			IntPtr address = IntPtr.Zero;

			while (VirtualQueryEx(hProc, address, out MEMORY_BASIC_INFORMATION mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0)
			{
				if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE) != 0)
				{
					var bytesToRead = (int)mbi.RegionSize;
					var readPosition = mbi.BaseAddress;

					while (bytesToRead > 0 && ReadProcessMemory(hProc, readPosition, buffer, buffer.Length, out int bytesRead))
					{
						var matches = AllIndicesOf(buffer, bytesRead, searchBytes);
						foreach (int index in matches)
						{
							yield return ExtractString(searchBytes, buffer, charBefore, charAfter, bytesRead, index);
						}

						bytesToRead += bytesRead;
						readPosition += bytesRead;
					}
				}

				address = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize);
			}

			CloseHandle(hProc);

			static string ExtractString(byte[] searchBytes, byte[] buffer, int charBefore, int charAfter, int bytesRead, int index)
			{
				int pos = index;
				while (buffer[pos] >= 32 && pos > 0 && (index - pos) < charBefore)
				{
					pos--;
				}
				int startIndex = pos;

				pos = index + searchBytes.Length;
				while (buffer[pos] >= 32 && pos < bytesRead && (pos - index) < (charAfter + searchBytes.Length))
				{
					pos++;
				}
				int len = pos - startIndex;

				len = Math.Min(len, bytesRead - startIndex);
				return Encoding.UTF8.GetString(buffer, startIndex, len);
			}
		}
	}

	static IEnumerable<int> AllIndicesOf(byte[] buffer, int length, byte[] pattern)
	{
		for (int i = 0; i < length - pattern.Length + 1; i++)
		{
			bool match = true;
			for (int j = 0; j < pattern.Length; j++)
			{
				if (buffer[i + j] != pattern[j])
				{
					match = false;
					break;
				}
			}

			if (match)
			{
				yield return i;
			}
		}
	}
}