<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * One runtime policy override.
 *
 * @property int $id
 * @property string $name
 * @property string $type
 * @property string|null $label
 * @property bool $enabled
 * @property array<string, mixed> $settings
 * @property string|null $updated_by
 * @property string|null $note
 * @property Carbon|null $updated_at
 */
final class SecurityPolicySetting extends Model
{
    protected $table = 'content_security_policies';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'settings' => 'array',
            'enabled' => 'boolean',
        ];
    }

    public function getConnectionName(): ?string
    {
        /** @var string|null $connection */
        $connection = config('content-security.persistence.connection');

        return $connection ?? parent::getConnectionName();
    }
}
