import os
import pickle
import hashlib
import string
import platform
import base64
import pickle
import string
import random
import pyperclip
from typing import Dict, Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes


class PasswordInfo:
    """Stores all information for a password entry."""
    def __init__(
        self, pass_id: int, username: str, email: str, 
        site: str, extra: str, password: str
    ):
        self.pass_id = pass_id      # Password ID
        self.username = username    # Username
        self.email = email          # Email
        self.site = site           # Site/App name
        self.extra = extra         # Extra details
        self.password = password    # Generated password


# Global variable to store decrypted passwords
passwords: Dict[int, PasswordInfo] = {}


def banner() -> None:
    banner = """\nooooooooo.         .o.       oooooo     oooo oooooooooooo ooooo      ooo
`888   `Y88.      .888.       `888.     .8'  `888'     `8 `888b.     `8'
 888   .d88'     .8"888.       `888.   .8'    888          8 `88b.    8
 888ooo88P'     .8' `888.       `888. .8'     888oooo8     8   `88b.  8
 888`88b.      .88ooo8888.       `888.8'      888    "     8     `88b.8
 888  `88b.   .8'     `888.       `888'       888       o  8       `888
o888o  o888o o88o     o8888o       `8'       o888ooooood8 o8o        `8\n"""
    return banner


def password_generator(
        length=8, upper=False, lower=False, nums=False, special=False
):
    """Generate a password by customized parameters."""
    chars = ''

    if upper:
        chars += string.ascii_uppercase
    if lower:
        chars += string.ascii_lowercase
    if nums:
        chars += string.digits
    if special:
        chars += string.punctuation

    passwd = ''.join(random.choices(chars, k=length))

    return passwd


def passwd_to_key(passwd):
    """Turn master password to key."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(passwd)
    return base64.urlsafe_b64encode(digest.finalize())


def encrypt(data, passwd):
    """Encrypt data with key."""
    key = passwd_to_key(passwd)
    f = Fernet(key)
    serialized = pickle.dumps(data)
    return f.encrypt(serialized).decode()


def decrypt(token, passwd):
    """Decrypt data with key."""
    try:
        key = passwd_to_key(passwd)
        f = Fernet(key)
        decrypted_bytes = f.decrypt(token.encode())
        return pickle.loads(decrypted_bytes)
    except InvalidToken:
        return None


def clear_screen():
    """Clears the terminal screen."""
    OS_NAME = platform.system()
    CLEAR_SCREEN = "cls" if OS_NAME == "Windows" else "clear"
    os.system(CLEAR_SCREEN)


def save(passwd: bytes):
    """Encrypts and saves passwords to a file."""
    with open("nothing.dat", "wb") as file:
        encrypted_data = encrypt(data=passwords, passwd=passwd)
        pickle.dump(encrypted_data, file)


def load_passwords(passwd: bytes):
    """Loads and decrypts passwords from file."""
    if os.path.exists("nothing.dat"):
        with open("nothing.dat", "rb") as file:
            encrypted_data = pickle.load(file)
            global passwords
            passwords = decrypt(token=encrypted_data, passwd=passwd)


def check_password(passwd: str):
    """Validates the master password."""
    if os.path.exists("sam.dat"):
        with open("sam.dat", "rb") as file:
            saved_passwd = pickle.load(file)
            if passwd == saved_passwd:
                return True
            else:
                print("\nInvalid password.")
    else:
        with open("sam.dat", "wb") as file:
            pickle.dump(passwd, file)
        return True


def new_password():
    """Creates a new password entry."""
    clear_screen()
    username = input("Enter username: ")
    email = input("Enter email: ")
    site = input("Enter website name or address: ")
    extra = input("Enter extra details: ")

    custom_password = input("Do want to generate random password? (y/n): ").upper()
    if custom_password == "Y":
        try:
            length = int(input("\nEnter password length (must be integer): "))
            if length <= 0:
                raise ValueError
        except ValueError:
            menu(msg="Password length must be a positive integer...")
            return

        upper = input(
            f"Include uppercase letters ({string.ascii_uppercase})? (y/n): "
        ).upper() == "Y"
        lower = input(
            f"Include lowercase letters ({string.ascii_lowercase})? (y/n): "
        ).upper() == "Y"
        nums = input(
            f"Include numbers ({string.digits})? (y/n): "
        ).upper() == "Y"
        special = input(
            f"Include special chars ({string.punctuation})? (y/n): "
        ).upper() == "Y"

        try:
            generated_pass = password_generator(
                length=length, upper=upper, lower=lower, nums=nums, special=special
            )
        except IndexError:
            menu(msg="Invalid password parameters...")
            return

        if not generated_pass:
            menu(msg="Invalid password parameters...")
            return
    else:
        generated_pass = str(input("Enter your password: "))

    # Assign the next available ID
    pass_id = max(passwords.keys(), default=0) + 1
    for existing_id in passwords:
        if existing_id + 1 not in passwords:
            pass_id = existing_id + 1
            break

    clear_screen()
    print(f"""
{'#' * 5} New Password ID: {pass_id} {'#' * 5}

Username: {username}
Email: {email}
Site: {site}
Description: {extra}

Password: {generated_pass}

{'#' * 30}
""")

    confirm = input("Continue? (Password will be copied) (y/n): ").upper()
    if confirm == "Y":
        pyperclip.copy(generated_pass)
        passwords[pass_id] = PasswordInfo(pass_id, username, email, site, extra, generated_pass)
        save(entry_passwd)
        menu(msg="Password saved and copied to clipboard!")
    else:
        menu(msg="Canceled...")


def find_password():
    """Searches passwords by any field."""
    clear_screen()
    query = input("Search by anything (ID, username, etc.): ")
    print(f"{'#' * 10} Results {'#' * 10}")

    found = False
    for pass_id, entry in passwords.items():
        if (query in str(pass_id) or 
            query.lower() in entry.username.lower() or 
            query.lower() in entry.email.lower() or 
            query.lower() in entry.site.lower() or 
            query.lower() in entry.extra.lower() or 
            query in entry.password):
            print(f"""
ID: {pass_id}
Username: {entry.username}
Email: {entry.email}
Site: {entry.site}
Description: {entry.extra}

Password: {entry.password}
{'-' * 40}""")
            found = True

    if not found:
        print("\nNo matches found.\n")

    try:
        selected_id = int(input(
            "\nEnter password ID to copy (0 to return to menu): "
        ))
        if selected_id < 0:
            menu(msg="Invalid input...")
        elif selected_id in passwords:
            pyperclip.copy(passwords[selected_id].password)
            menu(msg=f"Password (ID: {selected_id}) copied to clipboard!")
        elif selected_id == 0:
            menu(msg="Returning to menu...")
        else:
            menu(msg="ID not found...")
    except ValueError:
        menu(msg="Invalid input...")


def show_all_passwords():
    """Displays all saved passwords."""
    clear_screen()
    for entry in passwords.values():
        print(f"""
{'-' * 40}
ID: {entry.pass_id}
Username: {entry.username}
Email: {entry.email}
Site: {entry.site}
Description: {entry.extra}

Password: {entry.password}
{'-' * 40}""")

    try:
        selected_id = int(input("\nEnter ID to copy (0 to return to menu): "))
        if selected_id < 0:
            menu(msg="Invalid input...")
        elif selected_id in passwords:
            pyperclip.copy(passwords[selected_id].password)
            menu(msg=f"Password (ID: {selected_id}) copied to clipboard!")
        elif selected_id == 0:
            menu(msg="Returning to menu...")
        else:
            menu(msg="ID not found...")
    except ValueError:
        menu(msg="Invalid input...")


def edit_password():
    """Editing mode."""
    clear_screen()
    try:
        pass_id = int(input("Enter ID to edit (0 to cancel): "))
        if pass_id < 0:
            menu(msg="Invalid input...")
            return
    except ValueError:
        menu(msg="Invalid input...")
        return
    
    if pass_id == 0:
        menu(msg="Canceled...")
    elif pass_id in passwords:
        entry = passwords[pass_id]
        print(f"""
ID: {pass_id}
Username: {entry.username}
Email: {entry.email}
Site: {entry.site}
Description: {entry.extra}

Password: {entry.password}
{'-' * 40}""")
        new_username = input(f"\nEnter new username (old: {entry.username}): ")
        if not new_username:
            new_username = entry.username
        new_email = input(f"Enter new email (old: {entry.email}): ")
        if not new_email:
            new_email = entry.email
        new_site = input(f"Enter new website name or address (old: {entry.site}): ")
        if not new_site:
            new_site = entry.site
        new_extra = input(f"Enter new extra details (old: {entry.extra}): ")
        if not new_extra:
            new_extra = entry.extra
        new_password = input(f"\nEnter new password (old: {entry.password}): ")
        if not new_password:
            new_password = entry.password
        confirm = input("\nEdit this password? (old entries will be deleted) (y/n): ")
        if confirm.upper() == "Y":
            del passwords[entry.pass_id]
            passwords[entry.pass_id] = PasswordInfo(entry.pass_id, new_username, new_email, new_site, new_extra, new_password)
            pyperclip.copy(new_password)
            save(entry_passwd)
            menu(msg=f"Password with ID {entry.pass_id} edited and copied to clipboard!")
        else:
            menu(msg=f"Canceled...")
    else:
        menu(msg=f"ID not found...")
        

def remove_password():
    """Deletes a password entry by ID."""
    clear_screen()
    try:
        pass_id = int(input("Enter ID to remove (0 to cancel): "))
        if pass_id < 0:
            menu(msg="Invalid input...")
            return
    except ValueError:
        menu(msg="Invalid input...")
        return

    if pass_id == 0:
        menu(msg="Canceled...")
    elif pass_id in passwords:
        entry = passwords[pass_id]
        print(f"""
{'-' * 40}
ID: {pass_id}
Username: {entry.username}
Email: {entry.email}
Site: {entry.site}
Description: {entry.extra}

Password: {entry.password}
{'-' * 40}""")

        confirm = input("Delete this entry? (y/n): ").upper()
        if confirm == "Y":
            del passwords[pass_id]
            save(entry_passwd)
            menu(msg=f"Password (ID: {pass_id}) deleted!")
        else:
            menu(msg="Canceled...")
    else:
        menu(msg="ID not found...")


def reset_master_password():
    """Changes the master password."""
    clear_screen()
    old_pass = input("Enter current password: ").encode()
    hashed_old = hashlib.sha256(old_pass).hexdigest()

    if not check_password(hashed_old):
        menu(msg="Invalid password...")
        return

    new_pass = input("\nEnter new password: ").encode()
    confirm_pass = input("\nConfirm new password: ").encode()

    if new_pass != confirm_pass:
        menu(msg="Passwords don't match...")
        return

    hashed_new = hashlib.sha256(new_pass).hexdigest()
    with open("sam.dat", "wb") as file:
        pickle.dump(hashed_new, file)

    save(new_pass)
    clear_screen()
    print("Password changed successfully.\n\nPlease restart the program.")
    exit()


def wipe_all_passwords():
    """Deletes all saved passwords."""
    clear_screen()
    confirm = input("Delete ALL passwords? (y/n): ").upper()
    if confirm != "Y":
        menu(msg="Canceled...")
        return

    passwd = input("\nEnter master password to confirm: ").encode()
    hashed_pass = hashlib.sha256(passwd).hexdigest()

    if not check_password(hashed_pass):
        menu(msg="Invalid password...")
        return

    passwords.clear()
    save(entry_passwd)
    menu(msg="All passwords deleted!")


def exit_app() -> None:
    """Exits the program."""
    clear_screen()
    print("Goodbye\n")
    exit()


def menu(passwd: bytes = None, msg: str = "") -> None:
    """Main menu interface."""
    if passwd is None:
        passwd = entry_passwd

    hashed_pass = hashlib.sha256(passwd).hexdigest()
    if not check_password(hashed_pass):
        return

    clear_screen()
    print(f"""
        Raven Password Manager

{banner()}

Total passwords: {len(passwords)}

1. Create new password
2. Find a password
3. Show all passwords
4. Edit password
5. Remove a password
6. Reset master password
7. Delete ALL passwords
8. Exit (or 0)

{msg}
""")

    try:
        choice = int(input("Select option: "))
        if choice < 0:
            menu(msg="Invalid option...")
    except ValueError:
        menu(msg="Invalid option...")
        return

    actions = {
        1: new_password,
        2: find_password,
        3: show_all_passwords,
        4: edit_password,
        5: remove_password,
        6: reset_master_password,
        7: wipe_all_passwords,
        8: exit_app,
        0: exit_app
    }

    action = actions.get(choice, lambda: menu(msg="Invalid option..."))
    action()


# Entry point
if __name__ == "__main__":
    clear_screen()
    entry_passwd = input("Enter master password: ").encode()
    load_passwords(entry_passwd)
    menu()
