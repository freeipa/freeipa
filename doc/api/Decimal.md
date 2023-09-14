[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
.. _Decimal:

# Decimal
[//]: # (ADD YOUR NOTES BELOW. THESE WILL BE PICKED EVERY TIME THE DOCS ARE REGENERATED. //end)

A parameter for floating-point values (stored in the ``Decimal`` type).

Python Decimal type helps overcome problems tied to plain "float" type,
e.g. problem with representation or value comparison. In order to safely
transfer the value over RPC libraries, it is being converted to string
which is then converted back to Decimal number.
