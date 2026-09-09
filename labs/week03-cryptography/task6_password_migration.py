import hashlib
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


ph = PasswordHasher()


def store_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return False


def md5_hash(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def login(password: str, stored_hash: str):
    # Legacy MD5 password
    if len(stored_hash) == 32:
        if md5_hash(password) == stored_hash:
            print("Login successful")
            print("Legacy MD5 detected.")
            print("Migrating password to Argon2id...")

            new_hash = store_password(password)

            return True, new_hash

        return False, stored_hash

    # Argon2id password
    if verify_password(password, stored_hash):
        print("Login successful")
        return True, stored_hash

    return False, stored_hash


# Demonstration
password = "password123"

# Simulate an old MD5 password
old_hash = md5_hash(password)

print("=== Before Migration ===")
print("Stored MD5 hash:")
print(old_hash)

# Login and migrate
success, migrated_hash = login(password, old_hash)

print("\n=== After Login ===")
print("Login successful:", success)
print("Stored hash:")
print(migrated_hash)

# Verify migrated password
print("\n=== Verification ===")
print(
    "Argon2id verification:",
    verify_password(password, migrated_hash)
)