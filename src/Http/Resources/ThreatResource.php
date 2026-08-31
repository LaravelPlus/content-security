<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use LaravelPlus\ContentSecurity\Models\SecurityThreat;

/**
 * @mixin SecurityThreat
 */
final class ThreatResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        /** @var SecurityThreat $threat */
        $threat = $this->resource;

        return [
            'id' => $threat->id,
            'name' => $threat->name,
            'level' => $threat->level->value,
            'source' => $threat->source,
            'description' => $threat->description,
            'metadata' => $threat->metadata ?? [],
            'created_at' => $threat->created_at?->toIso8601String(),
        ];
    }
}
