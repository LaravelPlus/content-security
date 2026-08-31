<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use LaravelPlus\ContentSecurity\Domain\Policy\SecurityPolicy;

/**
 * @mixin SecurityPolicy
 */
final class PolicyResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        /** @var SecurityPolicy $policy */
        $policy = $this->resource;

        return $policy->toArray();
    }
}
