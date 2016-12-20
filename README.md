# sslscanalyzer
Shell script for converting an input file containing one or more `sslscan` results into HTML tables.

# Usage
You can provide a list of targets for the script to run `sslscan` against them for you, or provide your own input file of `sslscan` stdout.

```
./sslscanalyzer.sh [input file] [options]
```

* **[input file]** is required and must be the first parameter. It does not matter if the color-coded `sslscan` output was used or not.
* **-o [filename]**  allows you to specify an output filename. The default is 'sslscanalyzer-YYYY-MM-DD-HH-MM.html'. If the file name does not end in .htm o .html, then .html will be appended to it.
* **-r [value]** can be used to set a report format.
  - **-r 0** - Default. Minimal report format provides two columns - the host, and the accepted ciphers.
  - **-r 1** - Minimal report format - host, and a yes/no summary for different accepted connections (SSLv2, TLSv1.0, etc.).
  - **-r 2** - "Inverted" report format - one column for conditions (Accepts SSLv3, is vulnerable to Heartbleed, etc.), with the second column for affected hosts).
  - **-r 3** - Four column format - host, server checks (compression, heartbleed), accepted ciphers, and certificate details.
  - **-r 4** - Four column format, replacing accepted ciphers with yes/no summary.
  - **-r 5** - "Full" report format - different columns for things like session renegotiation, heartbleed, accepted ciphers, certificate issuer, certificate key, certificate expiration, etc.
  - **-r 6** - "Full" report format, replacing accepted ciphers with yes/no summary.
* **--do-sslscan** lets you run `sslscan --show-certificate` against each line of your input file, so that those results can be used instead of an input file already containing similar output from your own prior `sslscan` results.
* **--no-color** disables the default behavior of coloring the 'bad' results red. This currently applies to session renegotion, heartbleed, weak ciphers, certificate expiration, and certificates using sha1/md5 or 1024 bit signature encryption.
* **-h** - Displays help/usage information.
* **-q** - "Quiet" option. Disables the confirmation prompt at the beginning of the script, as well as the prompt that asks you if you want to open the HTML file using `sensible-browser`.
