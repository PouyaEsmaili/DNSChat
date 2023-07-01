from cmd import Cmd
import getpass

from client.services import ClientService


class SessionCmd(Cmd):
    prompt = 'DNSChat Session> '

    def __init__(self, client: ClientService):
        super().__init__()
        self.client = client

    def do_list(self, arg):
        users = self.client.list_users()
        for user in users:
            self.stdout.write(f'{user.username}{" (Online)" if user.online else ""}\n')

    def do_show(self, arg):
        username = arg.strip()
        messages = self.client.get_messages(username)
        key_id, _ = self.client.chat_keys.get(username, (None, None))
        if key_id is None:
            self.stdout.write(f'No chat key with {username}\n')
        self.stdout.write(f'Messages from {username} with key_id {key_id.hex()}:\n')
        for m in messages:
            self.stdout.write(f'{m["timestamp"]} - From {"you" if m["you"] else username}\n{m["text"]}\n\n')

    def do_send(self, arg):
        username = arg.strip()
        message = input('Message: ')
        self.stdout.write(self.client.send_message(username, message) + '\n')

    def do_expire(self, arg):
        password = getpass.getpass('Password: ')
        self.stdout.write(self.client.expire_session(password) + '\n')

    def do_create_group(self, arg):
        group_name = arg.strip()
        self.stdout.write(self.client.create_group(group_name) + '\n')

    def do_add_group_member(self, arg):
        group_name, username = arg.split()
        self.stdout.write(self.client.add_user_to_group(group_name, username) + '\n')

    def do_remove_group_member(self, arg):
        group_name, username = arg.split()
        self.stdout.write(self.client.remove_user_from_group(group_name, username) + '\n')

    def do_list_groups(self, arg):
        groups = self.client.list_groups()
        for group in groups:
            self.stdout.write(f'{group}\n')

    def do_show_group(self, arg):
        group_name = arg.strip()
        messages = self.client.get_group_messages(group_name)
        group_key_id = self.client.group_keys.get(group_name)
        if group_key_id is None:
            self.stdout.write(f'No chat in {group_name}\n')
            return
        self.stdout.write(f'Messages in {group_name} with key_id {group_key_id.hex()}:\n')
        for m in messages:
            self.stdout.write(f'{m["timestamp"]} - From {m["sender"]}\n{m["text"]}\n\n')

    def do_send_group(self, arg):
        group_name = arg.strip()
        message = input('Message: ')
        self.stdout.write(self.client.send_group_message(group_name, message) + '\n')

    def do_exit(self, arg):
        print("Exiting")
        return True


class MainCmd(Cmd):
    prompt = 'DNSChat> '

    def __init__(self, client: ClientService):
        super().__init__()
        self.client = client

    def do_register(self, arg):
        self.stdout.write("Registering\nUsername: ")
        username = self.stdin.readline().strip()
        password = getpass.getpass('Password: ')
        self.stdout.write(self.client.register(username, password) + '\n')

    def do_login(self, arg):
        self.stdout.write("Logging in\nUsername: ")
        username = self.stdin.readline().strip()
        password = getpass.getpass('Password: ')
        success, message = self.client.login(username, password)
        self.stdout.write(f'{message}\n')
        if success:
            cmd = SessionCmd(self.client)
            cmd.cmdloop()

    def do_exit(self, arg):
        print("Exiting")
        return True
