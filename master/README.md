﻿[![Build Status](https://travis-ci.org/tpoeppke/reds.svg?branch=master)](https://travis-ci.org/tpoeppke/reds)

#################################################
# Introduction
#################################################

ReDS stands for Revision controlled document storage.
With reds you can store your documents encrypted in the cloud 
and still have full control over them, 
because the encryption key is not stored at the cloud service provider.
Therefore even the cloud service provider can't access your data.
The encryption key is not stored anywhere else, so be careful not to lose it.

But that's not all. The integrity and authenticity of the stored documents is
ensured by means of digital signatures which are enforced by redsmaster for 
every head commit. Because of this, it is also possible to trace every change that 
was made back to it's author with non-repudiation of origin.

Moreover, there is also a built-in SSH server with user management and access control.
So you can share the documents with those you want to by giving them the address 
of the server running redsmaster.

They can just use a standard mercurial client to connect to the server at the 
specified port (standard: 2222). For example:
    
	hg clone ssh://averagejoe@yourserver:2222/your-repo
    
Redsmaster also supports public key login with SSH.



#################################################
# Requirements 
#################################################

To run redsmaster you need to have installed:

- s3ql
- python 2.7
- python-pip
- python-dev

Then simply install redsmaster using pip:
        
    pip install redsmaster

Or if you can't install it throug the Package Index, 
download the packed file and install it with:

	pip install path/to/redsmaster-x.y.z.zip
     
This packed file is available on the downloads page as well as the 
GnuPG signature file for it (redsmaster-x.y.z.zip.asc).

It is recommended to use a virtualenv for this. 

The user running redsmaster must be in the fuse group.



#################################################
# Usage
#################################################

Here is a short usage example for Amazon S3.

Setup the filesystem in an existing S3 bucket:
    
    redsmaster setup s3://your-bucket/
    
This will require your login information for S3. 
After this is finished you can start redsmaster by typing:

    redsmaster start s3://your-bucket/
    
Now you can access the repositories just like you would with a normal 
mercurial server. Note, that right now there are 2 standard users: 
guest and admin. They have no password so make sure to set them by typing:
    
    redsmaster adduser admin --password
    
This will prompt for the new password for admin.

Now, you can start playing with redsmaster and when you're finished just type:
    
    redsmaster stop
	
	
	
#################################################
# Changelog
#################################################
Version 1.0.4:
	- Fixed incompatibilities with Cement 2.4

Version 1.0.3:
	- Only a few small changes to prepare the next update
	
Version 1.0.2:
	- Initial release