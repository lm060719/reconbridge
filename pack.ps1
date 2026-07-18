# 将 module\ 目录打包成 KernelSU 刷入 zip（module.prop 位于 zip 根）。
# 关键：zip 内路径必须用正斜杠。Windows PowerShell 的 Compress-Archive 会写成反斜杠，
# 导致 KernelSU/Magisk 解压出错，故用内联 C# 助手保证正斜杠。
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$mod  = Join-Path $root "module"
$dist = Join-Path $root "dist"

if (-not (Test-Path (Join-Path $mod "bin\reconbridge_daemon"))) {
    throw "缺少 module\bin\reconbridge_daemon，请先运行 ./build.ps1"
}

New-Item -ItemType Directory -Force -Path $dist | Out-Null
$zip = Join-Path $dist "ReconBridge-M1.zip"

Add-Type -ReferencedAssemblies System.IO.Compression, System.IO.Compression.FileSystem -TypeDefinition @"
using System;
using System.IO;
using System.IO.Compression;
public static class RBZip {
  public static void Pack(string srcDir, string zipPath) {
    if (File.Exists(zipPath)) File.Delete(zipPath);
    using (var fs = new FileStream(zipPath, FileMode.Create))
    using (var arch = new ZipArchive(fs, ZipArchiveMode.Create)) {
      string baseDir = Path.GetFullPath(srcDir).TrimEnd('\\') + "\\";
      foreach (var f in Directory.GetFiles(srcDir, "*", SearchOption.AllDirectories)) {
        string rel = Path.GetFullPath(f).Substring(baseDir.Length).Replace('\\', '/');
        var entry = arch.CreateEntry(rel, CompressionLevel.Optimal);
        using (var es = entry.Open())
        using (var ins = File.OpenRead(f)) ins.CopyTo(es);
        Console.WriteLine("  + " + rel);
      }
    }
  }
}
"@

[RBZip]::Pack($mod, $zip)
$sz = [math]::Round((Get-Item $zip).Length / 1KB, 1)
Write-Host "OK -> $zip ($sz KB)"
