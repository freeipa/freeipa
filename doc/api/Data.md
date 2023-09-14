[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
.. _Data:

# Data
[//]: # (ADD YOUR NOTES BELOW. THESE WILL BE PICKED EVERY TIME THE DOCS ARE REGENERATED. //end)

Base class for the `Bytes` and `Str` parameters.

Previously `Str` was as subclass of `Bytes`.  Now the common functionality
has been split into this base class so that ``isinstance(foo, Bytes)`` wont
be ``True`` when ``foo`` is actually an `Str` instance (which is confusing).
