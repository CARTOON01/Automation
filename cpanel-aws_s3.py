import ftplib
import os
import logging
import boto3
import hashlib

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Fetching environment variables
FTP_SERVER = os.environ['FTP_SERVER']
FTP_USER = os.environ['FTP_USER']
FTP_PASSWORD = os.environ['FTP_PASSWORD']
FTP_REMOTE_DIR = os.environ['FTP_REMOTE_DIR']
S3_BUCKET = os.environ['S3_BUCKET']
S3_DEST_DIR = os.environ['S3_DEST_DIR']

s3 = boto3.client('s3')

def calculate_md5(file_path):
    """Calculate MD5 checksum of a file."""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def list_ftp_files_and_dirs(ftp_server, ftp_user, ftp_password, ftp_remote_dir):
    """List files and directories in the given FTP remote directory."""
    logger.info("Connecting to FTP server...")
    ftp = ftplib.FTP(ftp_server)
    
    try:
        ftp.login(ftp_user, ftp_password)
        logger.info(f"Logged in as {ftp_user}")
        
        try:
            ftp.cwd(ftp_remote_dir)
            logger.info(f"Changed to directory: {ftp_remote_dir}")
        except ftplib.error_perm as e:
            logger.error(f"Failed to change directory to {ftp_remote_dir}: {e}")
            return []
        
        filenames = ftp.nlst()
        logger.info(f"Found entries: {filenames}")
        
    except ftplib.all_errors as e:
        logger.error(f"FTP error: {e}")
        filenames = []
    
    finally:
        ftp.quit()
    
    return filenames

def check_s3_file_exists(bucket, key):
    """Check if the file exists in S3."""
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == '404':
            return False
        else:
            logger.error(f"Error checking S3 file existence: {e}")
            return False

def upload_to_s3(file_path, bucket, key):
    """Upload file to S3."""
    logger.info(f"Uploading file {file_path} to S3 bucket {bucket} with key {key}")
    s3.upload_file(file_path, bucket, key)

def process_ftp_directory(ftp_server, ftp_user, ftp_password, ftp_remote_dir, s3_dest_dir):
    """Process a directory from FTP and upload its contents to S3."""
    filenames = list_ftp_files_and_dirs(ftp_server, ftp_user, ftp_password, ftp_remote_dir)
    
    for filename in filenames:
        if filename in ['.', '..']:
            continue
        
        local_file_path = f"/tmp/{filename}"
        s3_key = os.path.join(s3_dest_dir, filename)
        
        if is_ftp_directory(ftp_server, ftp_user, ftp_password, filename, ftp_remote_dir):
            logger.info(f"Processing directory: {filename}")
            new_ftp_remote_dir = os.path.join(ftp_remote_dir, filename)
            new_s3_dest_dir = os.path.join(s3_dest_dir, filename)
            process_ftp_directory(ftp_server, ftp_user, ftp_password, new_ftp_remote_dir, new_s3_dest_dir)
        else:
            # Download file from FTP
            logger.info(f"Downloading file: {filename}")
            with open(local_file_path, 'wb') as local_file:
                with ftplib.FTP(ftp_server) as ftp:
                    ftp.login(ftp_user, ftp_password)
                    ftp.cwd(ftp_remote_dir)
                    ftp.retrbinary(f"RETR {filename}", local_file.write)
            
            if check_s3_file_exists(S3_BUCKET, s3_key):
                logger.info(f"File {filename} exists in S3. Checking for changes.")
                local_file_md5 = calculate_md5(local_file_path)
                s3_object = s3.get_object(Bucket=S3_BUCKET, Key=s3_key)
                s3_md5 = s3_object['ETag'].strip('"')
                
                if local_file_md5 == s3_md5:
                    logger.info(f"File {filename} has not changed. Skipping upload.")
                    os.remove(local_file_path)
                    continue
            
            # Upload file to S3
            upload_to_s3(local_file_path, S3_BUCKET, s3_key)
            os.remove(local_file_path)

def is_ftp_directory(ftp_server, ftp_user, ftp_password, name, remote_dir):
    """Check if a given name is a directory in FTP."""
    try:
        with ftplib.FTP(ftp_server) as ftp:
            ftp.login(ftp_user, ftp_password)
            ftp.cwd(remote_dir)
            ftp.cwd(name)
            return True
    except ftplib.error_perm as e:
        return False

def lambda_handler(event, context):
    try:
        logger.info("Starting FTP to S3 transfer")
        process_ftp_directory(FTP_SERVER, FTP_USER, FTP_PASSWORD, FTP_REMOTE_DIR, S3_DEST_DIR)
        
        return {
            'statusCode': 200,
            'body': 'Files and directories transferred successfully!'
        }
    except Exception as e:
        logger.error(f"Error in lambda_handler: {e}")
        return {
            'statusCode': 500,
            'body': str(e)
        }
