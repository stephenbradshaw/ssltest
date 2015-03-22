#ssltest
========

##What is it? 


SSLTest is a command line tool used to test SSL based servers to determine the  SSL ciphers and protocols they support.  These types of tests are commonly performed during penetration tests and compliance reviews (DSD ISM, PCI-DSS) that include a SSL server in scope.

It is a Perl program, that works on Linux, Windows and Mac OS X, and is originally based on Cryptonark by Chris Mahns.  It uses OpenSSL to make SSL connections, and test for supported ciphers and protocols.

##What can it do?

SSLTest has a number of interesting features that set it apart from other tools with a similar purpose:
* Checks compliance of detected ciphers and protocols against compliance standards such as DSD ISM and PCI-DSS.
* Optional greppable output, making the tool suitable to be run from a script, potentially against a large number of hosts, with the results able to be easily parsed by other command line tools.
* Colour coded output to provide a clearer indicator of which ciphers and protocols are supported under the currently selected compliance standard. Perfect for when you want to run the tool against a single host and quickly see from the command line whether the tested site is compliant or not, and if not, which ciphers or protocols are causing the non-compliance.  This feature was originally implemented in Cryptonark by Chris Mahns, and has been enhanced in this tool to support additional compliance standards and to also work on the Windows platform.
* Capability to test for certain protocols only (e.g. SSLv2, SSLv3 or TLS 1.0, 1.1 and 1.2 and any combination thereof).  If a host you are testing is freezing up when connections are made using certain protocols, you can choose to omit them.
* Includes basic logic to determine when an SSL cipher is supported only for the purpose of telling you to upgrade your browser.  Some HTTPS sites may allow an SSL connection to be established only to provide you a friendly message that a particular version of SSL is not supported.  This tool can (sometimes) tell when this occurs, and can help you avoid the false positive findings that might otherwise occur.  The tool also provides guidance on how to confirm that this behavior is the cause of a cipher not being listed as supported, should it occur.

##What should I know before using it?

Things you should be aware of when using the tool:
* SSLTest relies on OpenSSL to make SSL connections and confirm which ciphers and protocols are supported, and different versions of OpenSSL can introduce significant changes between versions that may affect the results provided by the tool.  A particular new (or old) version of OpenSSL may completely change the list of ciphers and protocols the tool thinks are supported, so any time you use this tool on a new system, or update OpenSSL or Perl, make sure you test the tool on a known system first before relying on its results.
* If running SSLTest on Windows, you should use ActiveStates ActivePerl to run the tool, as it will provide you with more flexibility about which version of OpenSSL is used.  Strawberry Perl compiles its OpenSSL modules using a particular version of OpenSSL code, but the modules used in the ActiveState Perl distribution uses OpenSSL dll files which can easily be replaced by the user to ensure a particular version of OpenSSL is used.  The last time I tested SSLTest on Strawberry Perl it did not work reliably, so I suggest you don't use it.
* The tool does use modules that do not come as standard on ActivePerl, but you will be given instructions by the tool on how to install these modules if they are not present.
* The tool has a fairly basic capability to detect when an SSL cipher is only supported in order to give you a message to update your browser - what Im calling a "friendly" SSL error message.  I am not aware of that many sites that do this, so this feature has not been tested extensively.  The tool will tell you if it is listing a cipher as unsupported because of this reason, and will tell you how you can confirm whether the finding is a false negative.  If you get these false negatives, or find sites that send these friendly SSL errors that are not properly detected by this tool, do let me know so I can further refine this feature.  Some more detail about this is provided here, and also in the tool help and source.
* Depending on the version of the underlying version of OpenSSL, you may get false negative responses for SSLv2 ciphers when scanning.  See this page for more information and some possible resolutions.
