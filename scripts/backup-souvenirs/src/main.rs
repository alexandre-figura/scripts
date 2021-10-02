use anyhow::{anyhow, Result};
use derive_new::new;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str;
use structopt::StructOpt;

// CLI Configuration

/// Save in the Cloud your collection of souvenirs.
#[derive(StructOpt)]
struct Cli {
    /// Directory containing your souvenirs on your machine
    #[structopt(parse(from_os_str))]
    dir: std::path::PathBuf,
    /// Name of your backup online
    backup: String,
}

// Script

fn main() {
    let args = Cli::from_args();

    let data_container = format!("{}--data", &args.backup);
    let segments_container = format!("{}--segments", &args.backup);

    let backup = OnlineBackup::new(data_container, segments_container);
    let dir = LocalDirectory::new(&Path::new(&args.dir));

    println!("Starting synchronization...");
    synchronize(&backup, &dir);
}

fn synchronize(backup: &OnlineBackup, dir: &LocalDirectory) {
    let remote_files = match backup.list() {
        Ok(files) => {
            println!("Backup's file list retrieved");
            files
        }
        Err(error) => panic!("Could not retrieve backup's file list: {}", error),
    };

    let local_files = match dir.scan() {
        Ok(files) => {
            println!("Local directory scanned");
            files
        }
        Err(error) => panic!("Could not scan local directory: {}", error),
    };

    for path in local_files {
        let rpath = path.strip_prefix(&dir.path).unwrap().to_str().unwrap();

        if remote_files.contains(&String::from(rpath)) == false {
            match backup.upload(&path, &rpath) {
                Ok(_output) => {
                    println!("{}", rpath)
                }
                Err(error) => {
                    println!("{}: could not upload file ({})", rpath, error)
                }
            };
        }
    }
}

// API

#[derive(new)]
struct OnlineBackup {
    data_container: String,
    segments_container: String,
    #[new(value = "104857600")]
    segments_size: u64,
}

impl OnlineBackup {
    fn list(&self) -> Result<Vec<String>> {
        let swift_list = Command::new("swift")
            .arg("list")
            .arg(&self.data_container)
            .output()?
            .stdout;

        let mut object_list = String::from_utf8(swift_list)?
            .lines()
            .map(|l| String::from(l))
            .collect::<Vec<String>>();

        object_list.sort_unstable();

        return Ok(object_list);
    }

    fn upload(&self, src: &Path, dst: &str) -> Result<()> {
        let swift_upload = if &src.metadata()?.len() > &self.segments_size {
            // Big file
            Command::new("swift")
                .arg("upload")
                .args(&["--object-name", &dst])
                .arg("--use-slo")
                .args(&["--segment-size", &format!("{}", &self.segments_size)])
                .args(&["--segment-container", &self.segments_container])
                .arg(&self.data_container)
                .arg(&src)
                .output()?
        } else {
            // Small file
            Command::new("swift")
                .arg("upload")
                .args(&["--object-name", &dst])
                .arg(&self.data_container)
                .arg(&src)
                .output()?
        };

        if swift_upload.status.success() {
            return Ok(());
        } else {
            return Err(anyhow!(String::from_utf8(swift_upload.stderr)?));
        }
    }
}

#[derive(new)]
struct LocalDirectory<'a> {
    path: &'a Path,
}

impl LocalDirectory<'_> {
    fn scan(&self) -> Result<Vec<PathBuf>> {
        let mut file_list: Vec<PathBuf> = Vec::new();
        self._scan(&self.path, &mut file_list)?;
        return Ok(file_list);
    }

    fn _scan(&self, dir: &Path, file_list: &mut Vec<PathBuf>) -> Result<()> {
        for entry in dir.read_dir()? {
            let path = entry?.path();

            if path.is_dir() {
                self._scan(&path, file_list)?;
            } else {
                file_list.push(PathBuf::from(&path));
            }
        }

        return Ok(());
    }
}
