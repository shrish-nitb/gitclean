#!/usr/bin/env python3

#gitclean v0.1.0-beta
#A CLI tool for cleaning git repositories that may contain sensitive information such as API keys, passwords, or other secrets.
#It provides a user-friendly interface to clean both the HEAD of important branches and the commit history of a git repository.
#It uses Docker to run Gitleaks for scanning secrets and BFG Repo-Cleaner for cleaning commit history.
#It also provides options for dry runs, manual cleanup, and handling of false positives.
#This script is designed to be run in a terminal or command prompt with Python 3.6+ installed.
#It requires Git, Docker, and Java (JRE or JDK) to be installed on the system.

# # Usage:
# pip install argparse colorama
# python gitclean.py <repo_url> [--bfg <path_to_bfg_jar>] [--dry-run] 
# Both <repo_url> and <path_to_bfg_jar> are optional, if not provided it will download the BFG Repo-Cleaner from the internet.
# --dry-run is an optional flag to skip committing and pushing changes after cleaning. Hence, it will only clean the repository and not push the changes to the remote repository. If not provided the script will commit and push the changes to the remote repository.
# --bfg is an optional argument to provide the path to the BFG Repo-Cleaner JAR file. If not provided, it will download the BFG Repo-Cleaner from the internet.

# shrish108@gmail.com
               
import os
import subprocess
import argparse
import shutil
import json
import logging
from pathlib import Path
from colorama import Fore, Style, init
import signal
init(autoreset=True)

BFG_URL = "https://repo1.maven.org/maven2/com/madgag/bfg/1.14.0/bfg-1.14.0.jar"
BFG_JAR_NAME = "bfg.jar"
MOUNTED=False

class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelno, "")
        message = super().format(record)
        return f"{color}{message}{Style.RESET_ALL}"

def docker_gitleaks_dir(path):
    run_cmd([
        "docker", "run", "--rm", "-v", f"{path}:/repo",
        "zricethezav/gitleaks:latest", "dir", "/repo", "--verbose"
    ], acceptable_codes=[0, 1])

def docker_gitleaks_git(path, report_path=None, verbose=False):
    cmd = [
        "docker", "run", "--rm", "-v", f"{path}:/repo",
        "zricethezav/gitleaks:latest", "git", "/repo"
    ]
    if report_path:
        cmd += ["-f=json", f"-r=/repo/{report_path}"]
    if verbose:
        cmd.append("--verbose")
    run_cmd(cmd, acceptable_codes=[0, 1])

def run_cmd(cmd: list, cwd: str = None, acceptable_codes: list = None):
    if acceptable_codes is None:
        acceptable_codes = [0]

    while True:
        logging.info(f"[CMD] {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, cwd=cwd)
            if result.returncode in acceptable_codes:
                return result  # Success, exit the loop
            else:
                logging.error(f"Command failed with code {result.returncode}")
        except Exception as e:
            logging.error(f"Unexpected error: {e}")

        # Ask for retry only if command failed
        retry = input("Do you want to retry the command? [y/N]: ").strip().lower()
        if retry != "y":
            exit(1)

def kill_processes_using_path(path: str):
    current_pid = os.getpid()

    try:
        result = subprocess.run(
            ["lsof", "-t", "+D", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if result.stdout:
            pids = set(int(pid) for pid in result.stdout.strip().split())
            for pid in pids:
                if pid != current_pid:
                    try:
                        os.kill(pid, signal.SIGKILL)
                        logging.info(f"Killed process {pid} using {path}")
                    except ProcessLookupError:
                        logging.info(f"Process {pid} no longer exists")
                    except PermissionError:
                        logging.warning(f"No permission to kill process {pid}")
        else:
            logging.info(f"No processes found using {path}.")
        
        if result.returncode > 1:
            logging.error(f"lsof error: {result.stderr.strip()}")

    except Exception as e:
        logging.error(f"Unexpected error running lsof: {e}")

def gitfilter_repo(repo_url, repo_name, work_dir, dry_run=False):
    global MOUNTED
    dmg_path = os.path.expanduser("~/CaseSensitiveGit.dmg")
    volume_path = "/Volumes/CaseSensitiveGit"
    gitfilter_repo_path = os.path.abspath(os.path.join(volume_path, "gitfilter-repo"))

    logging.info("Creating a case-sensitive disk image for gitfilter-repo...")
    if os.path.exists(dmg_path):
        logging.warning(f"Disk image {dmg_path} already exists. Skipping creation.")
    else:
        run_cmd([
            "hdiutil", "create", "-size", "1g", "-fs", "Case-sensitive HFS+",
            "-volname", "CaseSensitiveGit", dmg_path
        ])

    logging.info("Mounting the case-sensitive disk image...")
    run_cmd(["hdiutil", "attach", dmg_path])
    MOUNTED = True  # Only mark as mounted after successful attach

    os.chdir(volume_path)
    os.makedirs(gitfilter_repo_path, exist_ok=True)
    os.chdir(gitfilter_repo_path)

    logging.info("Cloning mirror of repository")
    run_cmd(["git", "clone", "--mirror", repo_url])

    mirror_path = os.path.join(gitfilter_repo_path, f"{repo_name}.git")
    secrets_txt_path = os.path.join(gitfilter_repo_path, "secrets.txt")
    report_file = os.path.join(mirror_path, "gitleaks-report.json")

    os.chdir(mirror_path)
    logging.info("Running gitleaks to scan the repository...")
    docker_gitleaks_git(os.getcwd(), "gitleaks-report.json")

    secrets = get_secrets_from_report(report_file)
    write_secrets_txt(secrets, secrets_txt_path)

    shutil.move(report_file, os.path.join("..", "gitleaks-report.json"))

    logging.info(f"Review and edit secrets.txt at: {secrets_txt_path}.")
    response = input("Type 'exit' to abort or press Enter to continue... ")
    if response.strip().lower() == "exit":
        logging.warning("Exiting as requested by user.")
        return

    if shutil.which("git-filter-repo") is None:
        logging.error("git-filter-repo is not installed.")
        return

    logging.info("Running git-filter-repo...")
    run_cmd([
        "git-filter-repo", "--sensitive-data-removal",
        "--replace-text", secrets_txt_path
    ])

    run_cmd(["git", "reflog", "expire", "--expire=now", "--all"])
    run_cmd(["git", "gc", "--prune=now", "--aggressive"])

    docker_gitleaks_git(os.getcwd(), verbose=True)

    if dry_run:
        logging.info("[DRY RUN] Skipping force-push.")
    else:
        if prompt_confirm("Force-push cleaned commit history and tags? "):
            run_cmd(["git", "push", "--force", "--all"])
            run_cmd(["git", "push", "--force", "--tags"])
        else:
            logging.warning("Force push skipped.")

    #remove gitfilter-repo directory
    os.chdir("..")
    logging.info("Removing gitfilter-repo directory...")
    shutil.rmtree(gitfilter_repo_path)  

    os.chdir(volume_path)
    os.chdir(work_dir)
    kill_processes_using_path(volume_path)
    logging.info(f"Returning to working directory: {os.getcwd()}")

    logging.info("Unmounting the case-sensitive disk image...")
    run_cmd(["hdiutil", "detach", volume_path])
    MOUNTED = False  # Mark as unmounted


def get_secrets_from_report(report_file):
    with open(report_file, "r") as f:
        try:
            report = json.load(f)
        except json.JSONDecodeError:
            logging.warning("Invalid JSON in gitleaks report")
            return []
    return list({entry["Secret"] for entry in report if "Secret" in entry})

def write_secrets_txt(secrets, output_path):
    with open(output_path, "w") as f:
        for secret in secrets:
            f.write(f"{secret}\n")

def prompt_confirm(message):
    answer = input(f"{message} [y/N]: ").strip().lower()
    return answer == "y"

def clean_working_directory(repo_path, branch, dry_run=False):
    os.chdir(repo_path)
    logging.info(f"Checking out branch: {branch}")
    run_cmd(["git", "checkout", branch])

    docker_gitleaks_dir(os.getcwd())

    response = input("[ACTION REQUIRED] Cleanup the files manually if secrets are found.\n"
                        "Ignore false positives, note them separately.\n"
                        "Type 'exit' to abort or press Enter to continue... ").strip().lower()
    if response == "exit":
        logging.warning("Exiting as requested by user.")
        exit(0)

    logging.info(f"Scanning after manual cleanup: {branch}")
    docker_gitleaks_dir(os.getcwd())

    if dry_run:
            logging.info(f"[DRY RUN] Skipping commit & push for branch: {branch}")
    else:
        if prompt_confirm("Do you want to commit and push changes? "):
            logging.info(f"Committing and pushing changes for branch: {branch}")
            run_cmd(["git", "add", "."])
            run_cmd(["git", "commit", "-m", f"Removed secrets from {branch}"])
            run_cmd(["git", "push", "origin", branch])
        else:
            logging.warning(f"[SKIPPED] Commit & push skipped for branch: {branch}")
    os.chdir("..")

def clean_commit_history(mirror_path, bfg_jar_path, secrets_txt_path, dry_run=False):
    os.chdir(mirror_path)
    report_file = os.path.join(mirror_path, "gitleaks-report.json")

    docker_gitleaks_git(os.getcwd(), "gitleaks-report.json")

    secrets = get_secrets_from_report(report_file)
    write_secrets_txt(secrets, secrets_txt_path)

    shutil.move(report_file, os.path.join("..", "gitleaks-report.json"))

    logging.info(f"Review and edit secrets.txt at: {secrets_txt_path}. For details, refer to gitleaks-report.json in same folder")
    logging.info("Remove any false positives you do NOT want BFG to replace.")
    response= input("Type 'exit' to abort or Press Enter to start removal process AFTER reviewing secrets.txt...")

    if response == "exit":
        logging.warning("Exiting as requested by user.")
        exit(0)

    run_cmd(["java", "-jar", bfg_jar_path, "--replace-text", secrets_txt_path, mirror_path])

    run_cmd(["git", "reflog", "expire", "--expire=now", "--all"])
    run_cmd(["git", "gc", "--prune=now", "--aggressive"])

    docker_gitleaks_git(os.getcwd(), verbose=True)
    
    logging.warning("If gitleaks still seen (except false positives) you can run a hard cleaning with flag --no-blob-protection then you're not protecting any commits, which means the BFG will modify the contents of even *current* commits which maybe holding up the dirty commits. This isn't recommended - ideally, if your current commits are dirty, you should fix up your working copy and commit that (From Step 1), check that your build still works, and only then run the BFG to clean up your history. Read more: https://rtyley.github.io/bfg-repo-cleaner/#protected-commits ")

    if prompt_confirm("Still you can try that as the final push will ask your confirmation. Do you want to proceed with hard cleaning? "):
        run_cmd(["java", "-jar", bfg_jar_path, "--replace-text", secrets_txt_path, "--no-blob-protection", mirror_path])

        run_cmd(["git", "reflog", "expire", "--expire=now", "--all"])
        run_cmd(["git", "gc", "--prune=now", "--aggressive"])
        docker_gitleaks_git(os.getcwd())
    else:
        logging.warning("[SKIPPED] Skipping hard cleaning with --no-blob-protection flag.")

    if dry_run:
        logging.info("[DRY RUN] Skipping force-push of cleaned commit history and tags.")
    else:
        if prompt_confirm("Do you want to force-push cleaned commit history and tags? "):
            logging.info("Force pushing cleaned commit history and tags.")
            run_cmd(["git", "push", "--force", "--all"])
            run_cmd(["git", "push", "--force", "--tags"])
        else:
            logging.warning("[SKIPPED] Force push skipped.")
    os.chdir("..")

def download_bfg():
    bfg_dir = Path.home() / ".bfg"
    bfg_dir.mkdir(parents=True, exist_ok=True)
    local_path = bfg_dir / BFG_JAR_NAME

    if local_path.exists():
        logging.info(f"BFG already downloaded at {local_path}")
        return str(local_path)

    logging.info(f"Downloading BFG Repo-Cleaner from {BFG_URL}")
    try:
        import urllib.request
        urllib.request.urlretrieve(BFG_URL, local_path)
        logging.info(f"[SUCCESS] Downloaded BFG to {local_path}")
        return str(local_path)
    except Exception as e:
        logging.error(f"Failed to download BFG: {e}")
        raise SystemExit(1)

def check_dependencies():
    logging.info("Checking required dependencies...")
    tools = {
        "git": "Git is required to manage repositories.",
        "docker": "Docker is required to run Gitleaks.",
        "java": "Java (JRE or JDK) is required to run BFG Repo-Cleaner.",
    }

    missing = []
    for tool, message in tools.items():
        if shutil.which(tool) is None:
            logging.error(f"[MISSING] '{tool}' not found: {message}")
            missing.append(tool)

    if missing:
        logging.critical(f"\nMissing required tools: {', '.join(missing)}")
        logging.critical("Please install the missing dependencies and try again.")
        exit(1)

    logging.info("[OK] All required dependencies are available.")

    try:
        subprocess.run(["docker", "info"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logging.info("[OK] Docker is running and accessible.")
    except subprocess.CalledProcessError:
        logging.critical("Docker is installed but not running or not accessible to this user.")
        logging.critical("→ Make sure the Docker daemon is running and your user is added to the 'docker' group.")
        exit(1)
    except Exception as e:
        logging.critical(f"Docker check failed: {e}")
        exit(1)


def main():
    try:
        # Setup logging first, before any other output
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.StreamHandler()]
        )
        
        print("gitclean v0.1.0-beta")
        print("A CLI tool for cleaning git repositories that may contain sensitive information such as API keys, passwords, or other secrets.")
        print("https://github.com/shrish-nitb/gitclean")

        print("For help run gitclean --help")
        
        parser = argparse.ArgumentParser(description="Git Secret Cleaner CLI")
        parser.add_argument("repo_url", help="URL of the git repository")
        parser.add_argument("--bfg", required=False, help="Path to BFG JAR (optional)")
        parser.add_argument("--dry-run", action="store_true", help="Skip committing and pushing changes")
        args = parser.parse_args()

        repo_name = Path(args.repo_url).stem
        work_dir = f"{repo_name}-gitclean"
        os.makedirs(work_dir, exist_ok=True)
        work_dir = os.path.abspath(work_dir)
        os.chdir(work_dir)
        
        log_path = os.path.abspath("cleaner.log")

        secrets_path = os.path.abspath("secrets.txt")
        gitleaks_report_path = os.path.abspath("gitleaks-report.json")
        if os.path.exists(secrets_path):
            os.remove(secrets_path)
        if os.path.exists(gitleaks_report_path):
            os.remove(gitleaks_report_path)

        # Reconfigure logging with color formatter and file handler
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
            
        formatter = ColorFormatter("%(asctime)s - %(levelname)s - %(message)s")
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        logging.basicConfig(
            level=logging.INFO,
            handlers=[
                logging.FileHandler(log_path, mode='a'),
                console_handler
            ]
        )
        logging.info(f"Starting Git Secret Cleaner CLI for repository: {args.repo_url}, working in {os.getcwd()}")
        check_dependencies()

        if not os.path.exists(repo_name):
            logging.info(f"Cloning repository {args.repo_url}")
            run_cmd(["git", "clone", args.repo_url])
        else:
            logging.warning(f"Repository {repo_name} already exists.")
            response = input(""
                "To erase all local uncommitted changes (tracked and untracked) type 'restore'.\n"
                "OR To delete this local copy and download again type 'discard'.\n"
                "OR To continue with this copy press Enter...\n"
                "OR To exit type 'exit'.\n"
            ).strip().lower()

            if response == "restore":
                logging.info("Erasing all local uncommitted changes (tracked and untracked)...")
                run_cmd(["git", "reset", "--hard"], cwd=repo_name)
                run_cmd(["git", "clean", "-fd"], cwd=repo_name)
                run_cmd(["git", "pull"], cwd=repo_name)
            elif response == "discard":
                logging.info("Deleting local copy and re-cloning repository...")
                shutil.rmtree(os.path.abspath(repo_name))
                logging.info(f"Recloning repository {args.repo_url}")
                run_cmd(["git", "clone", args.repo_url])
            elif response == "exit":
                logging.info("Exiting as requested by user.")
                exit(0)
            else:
                logging.warning("Continuing with existing repository, It may have any uncommited changes.")

        mirror_dir = f"{repo_name}.git"
        if not os.path.exists(mirror_dir):
            logging.info(f"Cloning mirror of repository {args.repo_url}")
            run_cmd(["git", "clone", "--mirror", args.repo_url])
        else:
            logging.warning(f"Mirror {mirror_dir} already exists.")
            response = input(""
                "To continue with this press Enter...\n"
                "OR To delete this local copy and download again type 'discard'.\n"
                "OR to exit type 'exit'.\n"
            ).strip().lower()

            if response == "discard":
                logging.info("Deleting local copy and re-cloning mirror of repository...")
                shutil.rmtree(os.path.abspath(mirror_dir))
                logging.info(f"Recloning repository {args.repo_url}")
                run_cmd(["git", "clone", "--mirror", args.repo_url])
            elif response == "exit":
                logging.info("Exiting as requested by user.")
                exit(0)

        backup_dir = f"{repo_name}-backup.git"
        if os.path.exists(backup_dir):
            logging.warning(f"Backup {backup_dir} already exists.")
            response = input(""
                "To continue with this backup press Enter...\n"
                f"OR To delete this backup and copy again from {mirror_dir} type 'discard'.\n"
                "OR to exit type 'exit'.\n"
            ).strip().lower()

            if response == "discard":
                logging.info(f"Removing existing backup at {backup_dir}")
                shutil.rmtree(backup_dir)
                logging.info(f"Creating new backup from mirror at {backup_dir}")
                shutil.copytree(mirror_dir, backup_dir)
            elif response == "exit":
                logging.info("Exiting as requested by user.")
                exit(0)
        else:
            logging.info(f"Creating backup from mirror at {backup_dir}")
            shutil.copytree(mirror_dir, backup_dir)

        bfg_path = args.bfg or download_bfg()
        mirror_path = os.path.abspath(mirror_dir)

        while True:
            logging.info("\n==== Main Menu ====")
            logging.info("1. Clean HEAD of important branches like release, master etc (Step 1)")
            logging.info("2. Clean commit history using BFG Repo-Cleaner (Step 2)")
            logging.info("3. Clean commit history using git-filter-repo (Step 2)")
            logging.info("4. Exit")
            choice = input("Enter your choice (1/2/3/4): ").strip()

            if choice == "1":
                branches_input = input("Enter the branch name(s) to clean (comma-separated): ").strip()
                if branches_input == "":
                    logging.warning("Branch name cannot be empty.")
                    continue
                branches = [b.strip() for b in branches_input.split(",") if b.strip()]
                for branch in branches:
                    logging.info(f"Cleaning branch '{branch}'")
                    clean_working_directory(repo_name, branch, dry_run=args.dry_run)

            elif choice == "2":
                logging.info("Starting commit history cleaning")
                clean_commit_history(mirror_path, bfg_path, secrets_path, dry_run=args.dry_run)

            elif choice == "3":
                logging.info("Starting commit history cleaning")
                gitfilter_repo(args.repo_url, repo_name, work_dir, dry_run=args.dry_run)

            elif choice == "4":
                logging.info("Exiting program.")
                logging.info("Exiting Git Secret Cleaner CLI")
                exit(0)
            else:
                logging.warning("Invalid choice. Please select 1, 2, 3, or 4.")
                
    except KeyboardInterrupt:
        logging.info("Exiting program due to keyboard interrupt.")
        logging.info("Exiting Git Secret Cleaner CLI due to keyboard interrupt.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        logging.error(f"An unexpected error occurred: {e}. Check the log file for details.")
    finally:
        # Always clean up regardless of success or failure
        logging.info("Gracefully shutting down gitclean...")
        try:
            os.chdir(work_dir)
        except:
            pass  # work_dir might not exist if script fails early

        # Hardcoded paths
        gitfilter_repo_path = "/Volumes/CaseSensitiveGit/gitfilter-repo"
        volume_path = "/Volumes/CaseSensitiveGit"

        try:
            if os.path.exists(gitfilter_repo_path):
                logging.info("Removing gitfilter-repo directory...")
                shutil.rmtree(gitfilter_repo_path)
        except Exception as cleanup_err:
            logging.warning(f"Failed to remove gitfilter-repo directory: {cleanup_err}")

        if MOUNTED:
            try:
                kill_processes_using_path(volume_path)
                logging.info("Unmounting the case-sensitive disk image...")
                run_cmd(["hdiutil", "detach", volume_path])
            except Exception as umount_err:
                logging.error(f"Failed to unmount volume: {umount_err}")


if __name__ == "__main__":
    main()