# Installing packages for Lambda Layers

1. Create a folder per Lambda Layer (Note: There's a hard limit of 5 layers
   per function). Example, `requests` in order to create a layer that
   contains the `requests` package
2. From each layer subdirectory, run:

```Shell
pip3 install -r requirements.txt -t python/lib/python3.7/site-packages/
```

This will read the contents of `requirements.txt` and install into the
directory tree specified after `-t`
