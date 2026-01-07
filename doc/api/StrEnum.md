[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
.. _StrEnum:

# StrEnum
[//]: # (ADD YOUR NOTES BELOW. THESE WILL BE PICKED EVERY TIME THE DOCS ARE REGENERATED. //end)
Enumerable for Unicode text (stored in the ``str`` type).

For example:

```
>>> enum = StrEnum('my_enum', values=('One', 'Two', 'Three'))
>>> enum.validate('Two', 'cli') is None
True
>>> enum.validate('Four', 'cli')
Traceback (most recent call last):
  ...
ValidationError: invalid 'my_enum': must be one of 'One', 'Two', 'Three'
```
