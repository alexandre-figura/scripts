use anyhow::Result;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::str;
use structopt::StructOpt;

// When a file is too big, it will get split into segments on Swift.
const MAX_FILE_SIZE: u64 = 104857600;

/// Save in the Cloud your collection of souvenirs.
#[derive(StructOpt)]
struct Cli {
    /// Where souvenirs are stored locally
    #[structopt(parse(from_os_str))]
    path: std::path::PathBuf,
    /// Where souvenirs will be uploaded to
    container: String,
}


// Backup a local directory into a remote Swift container.
fn backup(dir: &Path, container: &str) -> Result<()> {
    let swift_list = Command::new("swift")
                    .arg("list")
                    .arg(container)
                    .output();

    /*
    FIXME: borrowed value does not live long enough (output)
    let remote_files = match swift_list {
        Ok(output) => {
            match str::from_utf8(&output.stdout) {
                Ok(decoded) => decoded.lines().collect::<Vec<&str>>(),
                Err(_error) => {
                    let malformated = String::from_utf8_lossy(&output.stdout);
                    panic!("Could not decode Swift List output: {}", malformated);
                }
            }
        }
        Err(error) => panic!("Could not retrieve list of remote files: {}", error),
    };
    */
    
    let stdout = swift_list.unwrap().stdout;
    let mut remote_files = str::from_utf8(&stdout)?.lines().collect::<Vec<&str>>();
    remote_files.sort_unstable();

    scan_local_files(&dir, &dir, &container, &remote_files)?;

    Ok(())
}


fn scan_local_files(top_dir: &Path, dir: &Path, container: &str, remote_files: &Vec<&str>) -> Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                scan_local_files(&top_dir, &path, &container, &remote_files)?;
            } else {
                let relative_path = path.strip_prefix(&top_dir)?.to_str().unwrap();

                if remote_files.contains(&relative_path) {
                    println!("{}: already online", relative_path);
                } else {
                    upload_file(&path, &top_dir, &container)?;
                }
            }
        }
    }

    Ok(())
}


// Upload a local file to a remote Swift container.
fn upload_file(file: &Path, dir: &Path, container: &str) -> Result<()> {
    let relative_path = file.strip_prefix(&dir)?.to_str().unwrap();

    let swift_upload = if &file.metadata()?.len() > &MAX_FILE_SIZE {
        // Big file
        Command::new("swift")
                .arg("upload")
                .args(&["--object-name", relative_path])
                .arg("--use-slo")
                .arg("--segment-size")
                .arg(format!("{}", MAX_FILE_SIZE))
                .arg(&container)
                .arg(&file)
                .output()
    } else {
        // Small file
        Command::new("swift")
                .arg("upload")
                .args(&["--object-name", relative_path])
                .arg(&container)
                .arg(&file)
                .output()
    };

    match swift_upload {
        Ok(_output) => { println!("{}", relative_path) },
        Err(error) => { println!("{}: could not upload file ({})", relative_path, error) },
    }

    Ok(())
}


fn main() {
    let args = Cli::from_args();
    backup(&args.path, &args.container).unwrap();
}
