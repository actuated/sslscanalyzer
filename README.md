# sslscanalyzer
Shell script for converting an input file containing one or more `sslscan` results into HTML tables.

# Usage
```
./sslscanalyzer.sh [input file] [options]
```

* **[input file]** is required and must be the first parameter. It does not matter if the color-coded `sslscan` output was used or not.
* **-q** - "Quiet" option. Disables the confirmation prompt at the beginning of the script, as well as the prompt that asks you if you want to open the HTML file using `sensible-browser`.
* **--all-ciphers** - By default, the HTML report will list weak ciphers. This option will override that, to list all accepted ciphers.
*  **--cert-detail** - By default, certificate details (issuer, signature algorithm, key strength and expiration) are condensed into one table cell. This option allows you to break those out into separate columns.
* **--full** - By default, the session renegotiation and compression results are not put into the HTML table. This option adds them. This option assumes **--cert-details**.
