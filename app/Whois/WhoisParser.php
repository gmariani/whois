<?php

declare(strict_types=1);

namespace Whois\Whois;

/**
 * Best-effort parsing of free-form WHOIS text into the same shape that
 * RdapParser::domain() produces.
 */
final class WhoisParser
{
    /**
     * @return array<string,mixed>
     */
    public static function domain(string $registry, ?string $registrar): array
    {
        // Prefer the registrar's (thick) record for each field, fall back to the registry's.
        $text = trim(($registrar ?? '') . "\n" . $registry);

        $registrarName = self::first($text, [
            '/^\s*Registrar:[ \t]*(\S.*)$/mi',
            '/^\s*Sponsoring Registrar:\s*(.+)$/mi',
            '/^\s*Registrar:\s*\R\s+(.+)$/mi', // .uk: name on the next line
        ]);
        $registrarUrl = self::first($text, [
            '/^\s*Registrar URL:\s*(\S+)/mi',
            '/^\s*Registrar:\s*\R.+\R\s+URL:\s*(\S+)/mi',
        ]);
        if ($registrarUrl !== null && !preg_match('#^https?://#i', $registrarUrl)) {
            $registrarUrl = 'http://' . $registrarUrl;
        }

        $nameservers = [];
        if (preg_match_all('/^\s*(?:Name Server|nserver):\s*(\S+)/mi', $text, $m)) {
            $nameservers = $m[1];
        } elseif (preg_match('/^\s*Name servers?:[ \t]*\R((?:[ \t]+\S.*(?:\R|$))+)/mi', $text, $block)) {
            // .uk style: indented host lines, ending at the first blank line.
            preg_match_all('/^\s+(\S+)/m', $block[1], $hosts);
            $nameservers = $hosts[1];
        }

        $status = [];
        if (preg_match_all('/^\s*(?:Domain )?Status:\s*(\S+)/mi', $text, $m)) {
            $status = $m[1];
        }

        $dnssec = self::first($text, ['/^\s*DNSSEC:\s*(.+)$/mi']);
        $email = self::first($text, ['/^\s*Registrant Email:\s*(\S+@\S+)/mi']);

        return [
            'handle' => self::first($text, ['/^\s*Registry Domain ID:\s*(.+)$/mi']),
            'registrar' => $registrarName === null ? null : [
                'name' => $registrarName,
                'url' => $registrarUrl,
                'ianaId' => self::first($text, ['/^\s*Registrar IANA ID:\s*(\d+)/mi']),
                'abuseEmail' => self::first($text, ['/^\s*Registrar Abuse Contact Email:\s*(\S+)/mi']),
                'abusePhone' => self::first($text, ['/^\s*Registrar Abuse Contact Phone:\s*(\S+)/mi']),
            ],
            'created' => self::date(self::first($text, [
                '/^\s*Creation Date:\s*(.+)$/mi',
                '/^\s*Registered on:\s*(.+)$/mi',
                '/^\s*created:\s*(.+)$/mi',
            ])),
            'updated' => self::date(self::first($text, [
                '/^\s*Updated Date:\s*(.+)$/mi',
                '/^\s*Last updated:\s*(.+)$/mi',
                '/^\s*(?:changed|last-update):\s*(.+)$/mi',
            ])),
            'expires' => self::date(self::first($text, [
                '/^\s*Registry Expiry Date:\s*(.+)$/mi',
                '/^\s*Registrar Registration Expiration Date:\s*(.+)$/mi',
                '/^\s*(?:Domain )?Expiration Date:\s*(.+)$/mi',
                '/^\s*Domain expires:\s*(.+)$/mi',
                '/^\s*Expiry date:?\s+(.+)$/mi',
                '/^\s*paid-till:\s*(.+)$/mi',
            ])),
            'status' => array_values(array_unique($status)),
            'nameservers' => array_values(array_unique(array_map(fn ($ns) => strtolower(rtrim($ns, '.')), $nameservers))),
            'dnssec' => $dnssec === null ? null : !preg_match('/unsigned|no|inactive/i', $dnssec),
            'registrant' => [
                'name' => self::first($text, ['/^\s*Registrant Name:\s*(.+)$/mi', '/^\s*Registrant:\s*\R\s+(.+)$/mi']),
                'organization' => self::first($text, ['/^\s*Registrant Organi[sz]ation:\s*(.+)$/mi']),
                'email' => $email !== null && filter_var($email, FILTER_VALIDATE_EMAIL) ? $email : null,
                'phone' => null,
                'address' => null,
                'country' => self::first($text, ['/^\s*Registrant Country:\s*(.+)$/mi']),
            ],
        ];
    }

    /**
     * @param list<string> $patterns
     */
    private static function first(string $text, array $patterns): ?string
    {
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $text, $m) && trim($m[1]) !== '') {
                return trim($m[1]);
            }
        }
        return null;
    }

    private static function date(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }
        $time = strtotime($value);
        return $time === false ? $value : gmdate('Y-m-d\TH:i:s\Z', $time);
    }
}
