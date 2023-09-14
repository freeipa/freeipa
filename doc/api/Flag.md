[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
.. _Flag:

# Flag
[//]: # (ADD YOUR NOTES BELOW. THESE WILL BE PICKED EVERY TIME THE DOCS ARE REGENERATED. //end)

A boolean parameter that always gets filled in with a default value.

This `Bool` subclass forces ``autofill=True`` in `Flag.__init__()`.  If no
default is provided, it also fills in a default value of ``False``.
Lastly, unlike the `Bool` class, the default must be either ``True`` or
``False`` and cannot be ``None``.

For example:
```
>>> flag = Flag('my_flag')
>>> (flag.autofill, flag.default)
(True, False)
```

To have a default value of ``True``, create your `Flag` intance with
``default=True``.  For example:

```
>>> flag = Flag('my_flag', default=True)
>>> (flag.autofill, flag.default)
(True, True)
```

Also note that creating a `Flag` instance with ``autofill=False`` will have
no effect.  For example:

```
>>> flag = Flag('my_flag', autofill=False)
>>> flag.autofill
True
```
