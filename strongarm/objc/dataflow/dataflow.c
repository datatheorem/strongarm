/*  Example of wrapping cos function from math.h with the Python-C-API. */

#include <Python.h>
#include <math.h>

#if PY_MAJOR_VERSION < 3
#error "Must be using Python 3"
#endif

static PyObject* get_register_contents_at_instruction_fast(PyObject* self, PyObject* args) {
    double value;
    double answer;

    /*  parse the input, from python float to c double */
    if (!PyArg_ParseTuple(args, "d", &value))
        return NULL;
    /* if the above function returns -1, an appropriate Python exception will
     * have been set, and the function simply returns NULL
     */

    /* call cos from libm */
    answer = cos(value);

    /*  construct the output from cos, from c double to python float */
    return Py_BuildValue("f", answer);
}

static PyObject* trimmed_register_name(PyObject* self, PyObject* args) {
    /*
    Remove 'x', 'r', or 'w' from general purpose register name
    This is so the register strings 'x22' and 'w22', which are two slices of the same register,
    map to the same register.

    Will return non-GP registers, such as 'sp', as-is.

    Args:
          reg_name: Full register name to trim

    Returns:
          Register name with trimmed size prefix, or unmodified name if not a GP register
    */

    char* reg_name;
    char* trimmed_name = NULL;

    if (!PyArg_ParseTuple(args, "s", &reg_name)) {
        return NULL;
    }

    char prefixes[] = {'x', 'w', 'r'};
    for (unsigned long i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        char prefix = prefixes[i];
        if (reg_name[0] == prefix) {
            trimmed_name = strdup(&reg_name[1]);
            break;
        }
    }

    //if passed a non-general purpose register, return it as-is
    if (!trimmed_name) {
        trimmed_name = reg_name;
    }

    return PyUnicode_FromString(trimmed_name);
}

/*  define functions in module */
static PyMethodDef DataflowMethods[] = {
     {"get_register_contents_at_instruction_fast", get_register_contents_at_instruction_fast, METH_VARARGS, "analyze dataflow to determine the value in a register at an execution point"},
     {"trimmed_register_name", trimmed_register_name, METH_VARARGS, "trim a general-purpose register name"},
     {NULL, NULL, 0, NULL}
};

/* module initialization */
/* Python version 3*/
static struct PyModuleDef dataflowModuleDef = {
    PyModuleDef_HEAD_INIT,
    "dataflow",
    "strongarm dataflow analysis",
    -1,
    DataflowMethods
};

PyMODINIT_FUNC PyInit_dataflow(void) {
    return PyModule_Create(&dataflowModuleDef);
}

