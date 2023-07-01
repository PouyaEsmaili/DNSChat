from concurrent import futures

import grpc
from django.core.management.base import BaseCommand
# from grpc_reflection.v1alpha import reflection
from django.conf import settings

from server.services import ChatServicer
from common.api import dnschat_pb2, dnschat_pb2_grpc


def init_grpc_server(workers: int, address: str):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=workers))
    server.add_insecure_port(address)
    return server


class Command(BaseCommand):
    help = 'Serve GRPC Server'

    def handle(self, *args, **options):
        max_workers = settings.GRPC_MAX_WORKERS
        server = init_grpc_server(
            max_workers,
            '0.0.0.0:9200',
        )

        dnschat_pb2_grpc.add_ChatServicer_to_server(
            ChatServicer(), server
        )

        # service_names = (
        #     dnschat_pb2.DESCRIPTOR.services_by_name[
        #         'Chat'
        #     ].full_name,
        # )

        # reflection.enable_server_reflection(service_names, server)

        server.start()
        self.stdout.write(
            self.style.SUCCESS('Successfully started grpc server')
        )
        try:
            server.wait_for_termination()
        except KeyboardInterrupt:
            self.stdout.write(self.style.ERROR('Shutting down grpc server'))
        finally:
            server.stop(0)
