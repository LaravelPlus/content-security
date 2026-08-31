<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use LaravelPlus\ContentSecurity\Support\ScannerHealth;

/**
 * @mixin ScannerHealth
 */
final class ScannerHealthResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        /** @var ScannerHealth $health */
        $health = $this->resource;

        return [
            ...$health->toArray(),
            // The connection string is host:port or a socket path. Neither
            // is a secret, and an operator diagnosing an outage needs it.
            'connection' => $health->connection,
        ];
    }
}
