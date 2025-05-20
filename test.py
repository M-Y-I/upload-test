import boto3
from botocore.exceptions import ClientError
import os
import time

# --- AWS Cognito 設定 ---
# 以下のプレースホルダーをご自身の環境の値に置き換えてください
# !! 注意: 本番環境ではパスワードをコードに直接記述しないでください !!
REGION = '' # ご自身のユーザープールのリージョン
USER_POOL_ID = '' # ご自身のユーザープールID
APP_CLIENT_ID = '' # ご自身のアプリケーションクライアントID
IDENTITY_POOL_ID = ''
BUCKET_NAME = ''
FILE_PATH = ''
OBJECT_KEY = ''

# 認証を試すユーザーの情報
USERNAME = '' # ユーザー名
PASSWORD = '' # パスワード

# --- 認証を実行する関数 ---
def test_cognito_authentication(username, password, user_pool_id, app_client_id, region):
    """
    Cognitoユーザープールに対してユーザー認証を試みる。
    """
    # Cognito Identity Provider クライアントを作成
    client = boto3.client('cognito-idp', region_name=region)

    print(f"Attempting to authenticate user '{username}' with User Pool '{user_pool_id}'...")

    try:
        # initiate_auth API を呼び出し、認証を開始
        # AuthFlow='USER_PASSWORD_AUTH' はユーザー名とパスワードでの認証フロー
        response = client.initiate_auth(
            ClientId=app_client_id,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
            }
            # ClientMetadata={ # 必要に応じてクライアントに関するメタデータを渡す
            #     'my-custom-key': 'my-custom-value'
            # }
        )

        # --- 応答の確認 ---

        # 認証に成功した場合
        if 'AuthenticationResult' in response:
            auth_result = response['AuthenticationResult']
            print("\n--- Authentication Successful ---")
            print(f"ID Token: {auth_result.get('IdToken', 'N/A')}")
            print(f"Access Token: {auth_result.get('AccessToken', 'N/A')}")
            print(f"Refresh Token: {auth_result.get('RefreshToken', 'N/A')}")
            print(f"Expires In: {auth_result.get('ExpiresIn', 'N/A')} seconds")
            print(f"Token Type: {auth_result.get('TokenType', 'N/A')}")
            print("-------------------------------")
            return auth_result # 認証結果辞書全体を返す

        # 認証に追加のチャレンジが必要な場合 (MFA, 新しいパスワードの設定など)
        elif 'ChallengeName' in response:
            print("\n--- Authentication Challenge Required ---")
            print(f"Challenge Name: {response['ChallengeName']}")
            print(f"Session: {response.get('Session', 'N/A')}")
            print("Challenge Parameters:")
            for param, value in response.get('ChallengeParameters', {}).items():
                print(f"  {param}: {value}")
            print("-------------------------------------")
            # TODO: ChallengeName に応じた応答処理 (respond_to_auth_challenge) を実装する必要があります
            return None # チャレンジが発生した場合は認証完了ではないため None を返す

        # その他の応答 (通常はエラーとして扱われるべき)
        else:
             print("\n--- Unexpected Authentication Response ---")
             print(f"Response: {response}")
             print("--------------------------------------")
             return None


    except client.exceptions.NotAuthorizedException:
        print("\n--- Authentication Failed ---")
        print("Error: Incorrect username or password.")
        print("---------------------------")
        return None
    except client.exceptions.UserNotFoundException:
        print("\n--- Authentication Failed ---")
        print(f"Error: User '{username}' not found in the User Pool.")
        print("---------------------------")
        return None
    except client.exceptions.TooManyRequestsException:
        print("\n--- Authentication Failed ---")
        print("Error: Too many requests. Please try again later.")
        print("---------------------------")
        return None
    except ClientError as e:
        # その他 Boto3 ClientError (権限不足、設定エラーなど)
        print(f"\n--- Boto3 Client Error ---")
        print(f"Error: {e}")
        # エラーコードやメッセージを確認する場合
        # print(f"Error Code: {e.response['Error']['Code']}")
        # print(f"Error Message: {e.response['Error']['Message']}")
        print("--------------------------")
        return None
    except Exception as e:
        # その他予期せぬエラー
        print(f"\n--- An Unexpected Error Occurred ---")
        print(f"Error: {e}")
        print("----------------------------------")
        return None

# Cognito user authenticate and get ID token
def authenticate_user():
    client = boto3.client('cognito-idp', region_name=REGION)

    try:
        response = client.initiate_auth(
            ClientId=APP_CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': USERNAME,
                'PASSWORD': PASSWORD,
            }
        )
        return response['AuthenticationResult']['IdToken']
    except ClientError as e:
        print(f"Error authenticating user: {e}")

# Get temp AWS credentials with ID Token
def get_temp_credentials(id_token):
    cognito_identity = boto3.client('cognito-identity', region_name=REGION)

    response = cognito_identity.get_id(
        IdentityPoolId=IDENTITY_POOL_ID,
        Logins={
            f'cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}': id_token
        }
    )

    identity_id = response['IdentityId']

    credentials = cognito_identity.get_credentials_for_identity(
        IdentityId=identity_id,
        Logins={
            f'cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}': id_token
        }
    )

    return credentials['Credentials']

def create_upload_callback(total_size):
    bytes_transferred_so_far = 0
    def upload_progress(bytes_transferred):
        nonlocal bytes_transferred_so_far
        bytes_transferred_so_far += bytes_transferred
        percentage = (bytes_transferred_so_far / total_size) * 100
        print(f" Upload Progress: {bytes_transferred_so_far} / {total_size} bytes ({percentage:.2f}%)", end='\r')

# file upload to s3
def upload_file_to_s3(credentials):
    # create Boto3 S3 client
    s3_client = boto3.client(
        's3',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=REGION
    )

    total_file_size = os.path.getsize(FILE_PATH)
    progress_callback = create_upload_callback(total_file_size)

    print(f"uploading {FILE_PATH} to s3://{BUCKET_NAME}/{OBJECT_KEY} using temporary credentials...")
    start_time = time.time()

    # multi part upload
    s3_client.upload_file(FILE_PATH, BUCKET_NAME, OBJECT_KEY, Callback=progress_callback)
    end_time = time.time()
    duration = end_time - start_time
    print("Upload completed successfully.")
    print(f"Upload duration: {duration:.2f} seconds")

# --- スクリプトの実行 ---
if __name__ == "__main__":
    id_token = authenticate_user()

    if id_token:
        credentials = get_temp_credentials(id_token)
        if credentials:
            upload_file_to_s3(credentials)
        else:
            print("Failed to obtain temporary AWS credentials.")
    else:
        print("User authentication failed. Cannot proceed with upload")
