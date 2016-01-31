# sslscanalyzer
Shell script for converting an input file containing one or more `sslscan` results into HTML tables.

# Usage
```
./sslscanalyzer.sh [input file] [options]
```

* **[input file]** is required and must be the first parameter. It does not matter if the color-coded `sslscan` output was used or not.
* **-o [filename]**  allows you to specify an output filename. The default is 'sslscanalyzer-YYYY-MM-DD-HH-MM.html'. If the file name does not end in .htm o .html, then .html will be appended to it.
* **-r [value]** can be used to set a report format.
  - "Standard" report combines information for each host into three columns - SSL server checks, weak/supported ciphers, and certificate details.
  - "Full" report provides a separate column for each field.
  - **-r 0** - Default. Standard report with Yes/No summary for weak ciphers.
  - **-r 1** - Standard report listing each weak cipher accepted.
  - **-r 2** - Standard report listing each cipher accepted.
  - **-r 3** - Full report with Yes/No summary for weak ciphers.
  - **-r 4** - Full report listing each weak cipher accepted.
  - **-r 5** - Full report listing each cipher accepted.
* **--do-sslscan** lets you run `sslscan --show-certificate` against each line of your input file, so that those results can be used instead of an input file already containing similar output from your own prior `sslscan` results.
* **--no-color** disables the default behavior of coloring the 'bad' results red. This currently applies to session renegotion, heartbleed, weak ciphers, certificate expiration, and certificates using sha1/md5 or 1024 bit signature encryption.
* **-h** - Displays help/usage information.
* **-q** - "Quiet" option. Disables the confirmation prompt at the beginning of the script, as well as the prompt that asks you if you want to open the HTML file using `sensible-browser`.
