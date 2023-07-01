import grpc
from django.core.management.base import BaseCommand
from django.conf import settings

from client.cmd import MainCmd
from common.api import dnschat_pb2_grpc
from client.services import ClientService


class Command(BaseCommand):
    help = 'Start client'

    def handle(self, *args, **options):
        with grpc.insecure_channel(settings.SERVER_ADDRESS) as channel:
            stub = dnschat_pb2_grpc.ChatStub(channel)
            service = ClientService(stub)
            service.start_session()
            cmd = MainCmd(service)
            cmd.cmdloop()
