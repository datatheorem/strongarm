Plan for visualizing strongarm data
-----------------------------------

Often, I'm asked to look at a binary and see if it appears to be 'valid', or corrupted. This is in cases where 
gammaray fails to parse a binary, or Hopper/IDA fail to load it, etc. A recent example is the corrupt binary Venmo
keeps sending us.

When I'm asked to do this, I cobble together a script that simply calls some MachoBinary/MachoAnalyzer functions
and prints their output. It would be better if this process was automated, and anyone could use it.

There are a few good approaches:

A script that, when invoked on a binary, just dumps all relevant binary info. The user can then grep for what they're
interested in, or could specify it with flags. This would be similar to otool.

A visual tool, a la Hopper or IDA, that aggregates strongarm info and displays it in a GUI. strongeyes

Approaches tried
------------------------

I began by trying to reuse UIKit to throw together a simple UI. `UILabel` would have made displaying strongarm info
pretty simple, with how easy it is to lay out UI's, automatic font resizing to fit window width, etc. All in all,
using UIKit would save a lot of work. I tried writing a compatibility layer over `Python.framework` that made it easy
to transparently call Python methods from Objective-C. Unfortunately, I couldn't figure out how to make 
`Python.framework` work with virtualenvs, and thus was enable to access the strongarm module from Objective-C. 
That said, this remains a viable approach.

I also tried using existing Python GUI frameworks. While writing the GUI in Python is far from optimal, it removes the
work of writing an FFI to interact with the existing strongarm Python code. Specifically, I tried installing
PyGUI and a GTK wrapper. I was not able to successfully install either, but I'm sure I could if I devoted a bit more
time to it.

Plan
---------------------

strongpack

An idea I had was to come up with a serializable format for storing the binary information strongarm parses. This way,
an Objective-C-based GUI could consume this serialized data and display it natively, without needing a Python FFI.

Additionally, this would allow the info-dump script to be trivially created as well, by simply displaying the contents
of the serialized strongarm data.

The serialized format could simply be JSON. An example of a simple serialized binary might be:

```
{
    'name': 'YouTube',
    'segments': {
        'TEXT': {
            'sections': {
                '__text': {
                    'start': 0x1000,
                    'size': 0x1000,
                } 
            }
        },
        'DATA': {
            'sections': {
                '__data': {
                    'start': 0x2000,
                    'size': 0x1000,
                },
                '__la_symbol_ptr': {
                    'start': 0x3000,
                    'size': 0x1000,
                } 
            }
        }
    },
    'exported_symbols': {
        '_symbol_1',
        '_symbol_2',
    },
    'imported_symbols': {
        '_NSLog',
        '_objc_msgSend',
    },
    'objc_data': {
        'MyClass': {
            'superclass': 'NSObject',
            'selectors': {
                'selector1': {
                    'start': 0x1100,
                    'size': 0x50
                }
                'selector2': {
                    'start': 0x1200,
                    'size': 0x100
                }
            }
        }
    }
    'functions': {
        0x1100: {
            'calls': [
                {
                    'symbol': '_objc_msgSend',
                    'address': 0x1111,
                    'arg0': 'self',
                    'arg1': 'selector1',
                },
                {
                    'symbol': '_NSLog',
                    'address': 0x1121,
                    'arg0': '"Hello"',
                }
            ]
        }
}
```

A downside of this approach is that the GUI could not perform a `CodeSearch` without invoking strongarm, unless
strongpack really includes _all_ information parsed from strongarm, in which case `CodeSearch` would have to be 
reimplemented on the client-side to search using the JSON data. Alternatively, the former approach could be used: 
all information is packed into the JSON, and existing CodeSearch is reimplemented to search using the JSON format
instead. I do not think this is a good approach. 
