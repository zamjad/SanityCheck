# SanityCheck
Sanity_check of updated files after building artifacts. When building a large application with many moving pieces, it is easy to forget to update the building and move components to the appropriate location if you are not using the proper CI tool. 

This is an example of using AI to improve the programmers' productivity. The main structure of the program was written using an Artificial Intelligence tool and then updated to meet the needs. 

This simple utility captures the state of binary files (by default, *.exe and *.dll) before copying the new build artifacts and store in a file. After copying the build, rerun it to compare it with the older version and display the summary. 

It can be run in a batch file twice: first, capture the current state, then copy the build, and then compare.

```
python sanity_check.py capture --dir /path/to/dir --output capture.json --verbose
# Then copy files
python sanity_check.py compare --dir /path/to/dir --input capture.json --diffout diff.json --verbose --delete
```

The help of parameter can be get from one of the following way

```
python sanity_check.py help
python sanity_check.py -h
python sanity_check.py --help
```

If there is no change the output would be something like this in the output file defined in --diffout parameter

```
{
  "removed_files": [],
  "added_files": [],
  "modified_files": [],
  "summary": {
    "total_removed": 0,
    "total_added": 0,
    "total_modified": 0
  }
}
```
