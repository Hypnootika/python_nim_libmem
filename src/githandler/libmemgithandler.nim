import httpclient, json, os, std/[strutils], zippy/tarballs

const
  repoUrl = "https://api.github.com/repos/rdbo/libmem/releases"


proc downloadFile(url: string, localPath: string) =
  let client = newHttpClient()
  defer: client.close()
  echo "Downloading: ", url
  let response = client.getContent(url)
  writeFile(localPath, response)
  echo "Saved to: ", localPath

proc downloadLatestRelease() =
  let client = newHttpClient()
  defer: client.close()

  echo "Fetching latest release from GitHub..."
  let response = client.getContent(repoUrl)
  let json = parseJson(response)
  let assets = json[0]["assets"]
  for asset in assets:
    let asset_name = asset["name"].getStr
    let asset_download_url = asset["browser_download_url"].getStr
    when defined(windows):
      if "windows" in asset_name and "x86_64" in asset_name and "static-md" in asset_name:
        let temppath = "src/temp/libmem.tar.gz"
        let targetpath = "src/libmem"
        if not dirExists("src/temp"):
          createDir("src/temp")
          if not fileExists("src/temp/libmem.tar.gz"):

            downloadFile(asset_download_url, temppath)
            echo "Downloaded: ", asset_download_url
          else:
            echo "File already exists: ", temppath

        if dirExists(targetpath):
          removeDir(targetpath)
        extractAll(temppath, targetpath)
        removeDir("src/temp")
        moveDir(targetpath & "/" & asset_name.replace("tar.gz", "") & "/include/libmem", "src/libmem")
        moveDir(targetpath & "/" & asset_name.replace("tar.gz", "") & "/lib/release", "src/lib")
        removeDir(targetpath & "/" & asset_name.replace("tar.gz", ""))
    elif defined(linux):
      if "linux" in asset_name and "x86_64" in asset_name and "gnu-static" in asset_name:
        let temppath = "src/temp/libmem.tar.gz"
        let targetpath = "src/libmem"
        if not dirExists("src/temp"):
          createDir("src/temp")
          if not fileExists("src/temp/libmem.tar.gz"):

            downloadFile(asset_download_url, temppath)
            echo "Downloaded: ", asset_download_url
          else:
            echo "File already exists: ", temppath

        if dirExists(targetpath):
          removeDir(targetpath)
        extractAll(temppath, targetpath)
        removeDir("src/temp")
        moveDir(targetpath & "/" & asset_name.replace("tar.gz", "") & "/include/libmem", "src/libmem")
        moveDir(targetpath & "/" & asset_name.replace("tar.gz", "") & "/lib/release", "src/lib")
        removeDir(targetpath & "/" & asset_name.replace("tar.gz", ""))



when fileExists("src/libmem/libmem.h") or fileExists("src/lib/libmem.lib"):
  echo "libmem already exist, quitting..."
else:
  downloadLatestRelease()