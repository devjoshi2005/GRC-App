"""Credential validation for AWS, Azure, and OpenAI."""

import requests


def validate_aws(access_key_id: str, secret_access_key: str) -> dict:
    """Validate AWS IAM credentials using STS GetCallerIdentity."""
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError

        client = boto3.client(
            "sts",
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name="us-east-1",
        )
        resp = client.get_caller_identity()
        return {
            "valid": True,
            "account_id": resp.get("Account", ""),
            "arn": resp.get("Arn", ""),
            "message": f"AWS valid — Account {resp.get('Account', 'N/A')}",
        }
    except ClientError as e:
        return {"valid": False, "message": f"AWS error: {e.response['Error']['Message']}"}
    except NoCredentialsError:
        return {"valid": False, "message": "AWS credentials not provided"}
    except ImportError:
        return {"valid": False, "message": "boto3 not installed — run pip install boto3"}
    except Exception as e:
        return {"valid": False, "message": f"AWS error: {str(e)[:120]}"}


def validate_azure(client_id: str, tenant_id: str, client_secret: str) -> dict:
    """Validate Azure Service Principal via OAuth2 token endpoint."""
    try:
        url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://management.azure.com/.default",
            "grant_type": "client_credentials",
        }
        resp = requests.post(url, data=data, timeout=15)
        if resp.status_code == 200:
            return {
                "valid": True,
                "message": f"Azure SP valid — Tenant {tenant_id[:8]}...",
            }
        error = resp.json().get("error_description", "Unknown error")
        return {"valid": False, "message": f"Azure error: {error[:120]}"}
    except requests.exceptions.Timeout:
        return {"valid": False, "message": "Azure validation timed out"}
    except Exception as e:
        return {"valid": False, "message": f"Azure error: {str(e)[:120]}"}


def validate_openai(api_key: str, model: str = "gpt-4o") -> dict:
    """Validate OpenAI API key by listing models."""
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        resp = requests.get(
            "https://api.openai.com/v1/models", headers=headers, timeout=10
        )
        if resp.status_code == 200:
            models = [m["id"] for m in resp.json().get("data", [])]
            avail = model in models
            return {
                "valid": True,
                "model_available": avail,
                "message": f"OpenAI valid — {model} {'available' if avail else 'not in list (may still work)'}",
            }
        elif resp.status_code == 401:
            return {"valid": False, "message": "Invalid OpenAI API key"}
        return {"valid": False, "message": f"OpenAI HTTP {resp.status_code}"}
    except Exception as e:
        return {"valid": False, "message": f"OpenAI error: {str(e)[:120]}"}
