
# mod_md - Let's Encrypt for Apache - Charlotta branch

Copyright (c) 2020 Timothe Litt - Apache License

This document describes the changes in the `Charlotta` branch of `mod_md` - hopefully to be adopted by the `master` branch.  The changes are too extensive to be described in the ChangeLog, and would be difficult to review if scattered through the README.  

The material in this file should be merged into the README and the official documentation when everything has been finalized and a decision made to merge.

# Management Interface

`mod_md` can provide a management interface, which provides information
about `mod_md`, and the certificates that it manages.  It also provides
the ability to manually renew or revoke certificates, and the ability
to verify that they are correctly installed on the host systems for which
they are issued.  Additional information about the Certificate Authority(s)
and your accounts there is also provided. 

## Key features
 - Summary of all Managed Domains (certificates) - type, status, validity period, CA & activity
 - Drill-down to each subject (host) allows:
   - Verify that a TLS connection can be made - directly or with known **STARTTLS** protocols
   - Verifies each certificate's chain of trust
   - Extraction of the actual certificate(s), including intermediate certificates from the host
   - Displays any **DNS-01** validation records that are installed (usually need cleanup)
   - Inspects each certificate (private key) type separately - detects misconfigurations.
 - Drill-down to the Certificate Authority
   - Display's published metadata, typically including terms of service, website, CAA identities
   - Displays any CAA records installed in the DNS that are applicable to any subject in the domain.
   - If no CAA records are found, indicates what the CA should accept.
  - Manual operations (At this writing, not yet active)
   - 2-click manual forced renewal and/or revocation of certficates
   - 2-click account key rollover
   - Account key import (from some other ACME clients)
  - Very easy setup - no extra files, just one <Location> (must be secured) and one directive.
    - Everything necessary is built-in to `mod_md`
  - Flexible - directives allow custom appearance, unusual configurations
    - Some very unusual configurations require `configure` options and building from source.
  - CA-neutral - any ACME CA should work.   `mod_md` is tested with Let's Encrypt, but when other ACME CAs appear, the default (formerly hard-coded) can be changed in `configure`.

Enabling the management interface can involve a number of
configuration directives, most of which have reasonable defaults.

## Minimal setup

Although there are a lot of options, a minimal setup would be:

````
MDManageGUI on
<Location /mdmanager>
  SetHandler md-manage
  AuthType Basic
  AuthName "Managed Domain Management"
  AuthUserFile "/etc/httpd/md/passwords"
  require valid-user
  Require ip 2001:0db8::42:42 203.0.113.242
</Location>

$ htpasswd -c /etc/httpd/md/passwords mod_md_user
New password:
Re-type new password:
Adding password for user mod_md_user
$ chmod o=,g=r /etc/httpd/md/passwords; chown root.apache /etc/httpd/md/passwords

# If you use SeLinux:
$ semanage port -a -t http_port_t -p tcp 280
````

You would place this in any desired `<VirtualHost>`(s).  You should include at
least one `<VirtualHost>` that does **not** require SSL/TLS, since you may need
access to troublshoot any problems involving certificates.  You do **not** need
to place it in every `<VirtualHost>` - all managed certificates are visible from
any instance of the GUI.

Of course, you would specify your own trusted IP addresses, and might also want
to add stronger authentication.  Users must be allowed both **GET** and **POST**.

You **must** have some form of authentication enabled for the GUI.  If no authentication
is configured, all of the GUI URLs will return "Service Uavailable".

The URI space under the &lt;Location&gt; that you choose is managed by `mod_md`
and should have the same authentication.  Specifically, `path_info` is used to
serve certain resources and must be accessible to GUI users.

## Configuration directives

The complete list of configuration directives follows:

**MDManageGUI** on|off [port]

  Default: **off**

  Context: Global

  Enables the management Graphical User Interface handler.

  **Port** specifies a TCP port on `localhost` (`127.0.0.1`) for internal communications.
  Default: `280`.  **Note:** *traffic is not encrypted, but is signed. The protocol is volatile, not generally useful, and only supported for communications within the `mod_md` subsystem.*

**MDManageGUIStylesheet** URLspec

  Default: **none**

  Context: Global

  Allows you to customize the appearance of the GUI.  A stylesheet is
  built-in, so it is not necessary to specify this directive.

**MDManageGUILogo** URLspec

  Default: **none**

  Context: Global

  Allows you to customize the appearane of the GUI by adding a logo.
  A stadard logo - *ACME-LOGO.jpg* - is distributed with `mod_md`, but
  is not displayed unless you make it accessible at a URL specified by
  `MDManageGUILogo`.  A logo is optional, so it is not necessary to
  specify this directive.

**MDTrustedCAfile** filespec

  Default: Configured from the Curl library according to system type

  Context: Global

  Specifies the trusted (root) certificate "bundle" file that is used
  when communicating with the CA (e.g. Let's Encrypt) servers, and for
  some management functions.  This is a set of PEM certificates in no
  particular order.  Curl provides an update script, or it may be updated
  by your OS distribution.  The default normally works.

**MDTrustedCApath** directoryspec

  Default: Configured from the Curl library according to system type

  Context: Global

  Specifies directory containing the trusted (root) certificates, one
  per file named according their hash.  See the OpenSSL documentation
  for details.  The MDTrustedCAfile is consulted first, so there is
  generally no point in configuring both.  Using the MDTrustedCApath
  may save memory when only a few CAs are used.  OpenSSL's c_rehash
  script is usually used to setup this directory. The default normally
  is none, which works as long as you have a MDTrustedCAfile.

### Modified directive

**MDCertificateAuthority** url [display name]

  **MDCertificateAuthority** takes an optional second argument, which is
the name used to display the CA in the server status and management GUI pages.

Names for the Let's Encrypt URLs are predefined (as before).  This allows you
to specify a meaningful name for other CAs.  

If the display name parameter is omitted, the any previously-specified name will
be used.  Thus, if a URL appears in more than one **MDCertificateAuthority** 
directive, it need only be specified for the first.

If a display name is never specified for a URL, the hostname of the URL is used.

The default CA url and display name can be modified in `configure`.

## Specify a location

In addition to enabling the handler, you **must** make it available at at
one location.  Access to this location should be restricted to your
administrators.  This can be done with any of the HTTPD authorization
mechanisms: Basic (recommended only with https), digest, client
certificate, etc.  

Requiring https may be an issue if you need to diagnose
a certficate problem, so we recommend allowing http access from a
trusted IP address.  

# Build changes
The following changes have been made that affect building `mod_md` from source, all of which default to a working configuration.  There is considerable flexibility - but unless you have special requirements, the defaults will work out-of-the-box, and are recommended.

## Additions to `configure`
### Options
 - `--with-default-ca`=URL Specifies the URL of the ACME directory of the default CA, defaulting to Lets's Encrypt's production CA.
 - `--with-default-ca-name`=string Specifies a description for the default CA, defaulting to "Let's Encrypt"
 - `--with-jQuery`=url Specifies the URL from which the jQuery code is loaded.  The default is the [jQueryCDN](https://code.jquery.com/).  You can download this to your server, or use another CDN, depending on your preferences.
 - `--with-jQueryUI`=url Specifies the URL from which the jQueryUI code is loaded.  The default is the [jQueryCDN](https://code.jquery.com/ui/).  You can download this to your server, or use another CDN, depending on your preferences.
 - `--with-jQueryUITheme`=url Specifies the URL from which the jQuery base stylesheet (CSS) is loaded.  The default is the [jQueryCDN](https://code.jquery.com/ui/).  Note the link on this page is labelled "theme", not the code.  There are several themes to choose from, or you can customize.  The default is the "base" theme.  You can download this to your server, or use another CDN, depending on your preferences.  jQueryUI themes reference images as `images/<file>` relative to the `.css`, so when self-hosting, be sure to include the `images/` sub-directory and make it accessible.  You can futher customize appearance using the **MDManageGUIStylesheet** directive.
 - `enable-system-dns-servers` `mod_md` will use the system-configured DNS servers (`/etc/resolv.conf` on Unix; the "IP Helper" on Windows) when checking DNS records.  By default, public servers are used, which is preferable since they will provide the same view that the CA's validation process uses.  This may not be true of locally-configured or internal servers.
 - `--with-public-dns`=list Specifies the public DNS services to be used as a default, fallback, or when `--disable-system-dns-servers` is specified.  The list can be any combination of IPv4 and/or IPv6 addresses.  They are used in order - there isn't much benefit to a very long list.  The important thing is that they have the same view of the DNS as your CA does.
 - `--with-debug-js`=url Specifies a local URI from which the GUI javascript is provided.  This is a developer-only option that is **not** supported for production use because the javascript API is volatile.  Normally, the GUI javascript is provided from data compiled-in to `mod_md`.

### Automagic
 - configure determines the (system-specific) location of the trusted certificate store used when communicating with the CA (Typically Let's Encrypt).  This is also used by the management interface.  The selection can be overriden with the **MDTrustedCAfile** and/or **MDTrustedCApath** directives.

## Additions to the build
 - Every build will automagically update a file that will contain the build version if the build is done in a `git` working directory.  (Otherwise it is guaranteed to be empty.)  This is helpful in the development environment, as it will include the nearest tag and commit hash, as well as an indicator if uncommited files were included.  For this reason, it is important to `git tag` each release.
  - The GUI adds a number of files to the build, some of which are automatically generated.  This is handled by `automake` and `Makefile` helper scripts.  Any custom build/packaging may need changes.

## Minor maintainability/manageability changes

 - The options used to `configure` `mod_md` are logged at startup.
 - Allowed methods are properly reported in the Allow header and the correct 405 error is returned for unsupported access method requests to the status handler.
 - More compiler warnings squashed at some debugging optimization levels.

## Loose ends
- Does CMAKE need any changes?  The same new options as configure?
- This file could use some screenshots.

