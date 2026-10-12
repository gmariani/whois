<?php

declare(strict_types=1);

namespace Whois\Sections;

use Whois\Lookup\Context;

/**
 * One independently-loadable part of the results page.
 */
interface Section
{
    /**
     * @return array<string,mixed> JSON-serializable data for the front-end
     */
    public function build(Context $context): array;
}
