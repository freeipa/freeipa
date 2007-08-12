from turbogears.database import PackageHub
from sqlobject import *

hub = PackageHub('ipagui')
__connection__ = hub

# class YourDataClass(SQLObject):
#     pass

