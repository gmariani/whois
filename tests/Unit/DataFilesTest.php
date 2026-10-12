<?php

declare(strict_types=1);

namespace Whois\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Whois\Support\DataFile;

/**
 * Sanity checks for the hand-edited lists in app/data/. Run after editing them.
 */
final class DataFilesTest extends TestCase
{
    private const NAME = '/^[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9_])?$/';

    public function testSubdomainNames(): void
    {
        $data = DataFile::load('subdomains');
        foreach (['hosts', 'mx', 'https', 'txt', 'srv'] as $group) {
            self::assertNotEmpty($data[$group], $group);
            foreach ($data[$group] as $name) {
                self::assertMatchesRegularExpression(self::NAME, $name, "subdomains.php [{$group}]: '{$name}' is not a valid lower-case DNS name");
            }
            self::assertSame([], self::duplicates($data[$group]), "subdomains.php [{$group}] has duplicates");
        }
        foreach ($data['srv'] as $name) {
            self::assertMatchesRegularExpression('/^_[a-z0-9-]+\._(tcp|udp|tls)$/', $name, "SRV names look like _service._proto: '{$name}'");
        }
    }

    public function testDkimSelectors(): void
    {
        foreach (DataFile::load('dkim-selectors') as $selector => $provider) {
            self::assertMatchesRegularExpression(self::NAME, (string) $selector, "dkim-selectors.php: '{$selector}'");
            self::assertIsString($provider);
            self::assertNotSame('', $provider);
        }
    }

    public function testProviderTables(): void
    {
        $providers = DataFile::load('providers');
        self::assertSame(['registrars', 'organizations', 'dns', 'email'], array_keys($providers));

        foreach ($providers as $table => $entries) {
            $needles = array_map('strval', array_keys($entries));
            foreach ($entries as $needle => $label) {
                $needle = (string) $needle;
                self::assertSame(strtolower($needle), $needle, "providers.php [{$table}]: needles must be lower case ('{$needle}')");
                self::assertGreaterThanOrEqual(3, strlen($needle), "providers.php [{$table}]: '{$needle}' is too short to be safe");
                if ($table === 'email') {
                    self::assertIsArray($label, "providers.php [email] '{$needle}' => ['Name', isGateway]");
                    self::assertIsString($label[0]);
                    self::assertIsBool($label[1]);
                } else {
                    self::assertIsString($label, "providers.php [{$table}] '{$needle}'");
                }
            }

            // A needle listed after one of its own substrings can never be reached.
            foreach ($needles as $i => $later) {
                foreach (array_slice($needles, 0, $i) as $earlier) {
                    self::assertStringNotContainsString(
                        $earlier,
                        $later,
                        "providers.php [{$table}]: '{$later}' is shadowed by '{$earlier}' above it; move it higher",
                    );
                }
            }
        }
    }

    /**
     * @param list<string> $values
     * @return list<string>
     */
    private static function duplicates(array $values): array
    {
        return array_values(array_unique(array_diff_assoc($values, array_unique($values))));
    }
}
