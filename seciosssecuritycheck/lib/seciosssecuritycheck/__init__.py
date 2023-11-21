# seciosssecuritycheck package

"""
Constants
"""
TIMEOUT = 300
DATA_DIR = '/tmp/securitycheck.'


from .securitycheck import SecurityCheck, throw
from .service.aws import AWS
from .service.azure import Azure
from .service.gcp import Gcp

__all__ = ['AWS', 'Azure', 'Gcp']