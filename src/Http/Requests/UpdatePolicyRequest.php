<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Validator;

/**
 * The validation on this request is a security control, not a convenience.
 *
 * It is the boundary between "an administrator adjusted a limit" and "an
 * administrator, or anyone who reached an administrator's session, turned
 * the upload endpoint into a webshell drop." So: extensions are matched
 * against a strict pattern and screened against the forbidden list, sizes
 * are bounded by the config ceiling, and unknown keys never reach the
 * repository.
 */
final class UpdatePolicyRequest extends FormRequest
{
    public function authorize(): bool
    {
        // The route already ran the Authorize middleware.
        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        $ceiling = (int) config('content-security.files.max_size_ceiling', 512 * 1024 * 1024);

        return [
            'type' => ['required', Rule::in(['file', 'text'])],

            'label' => ['sometimes', 'string', 'max:120'],

            // File policies.
            'max_size' => ['sometimes', 'integer', 'min:1024', 'max:'.$ceiling],
            'extensions' => ['sometimes', 'array', 'max:200'],
            'extensions.*' => ['string', 'max:16', 'regex:/^[a-z0-9]{1,16}$/i'],
            'mime_types' => ['sometimes', 'array', 'max:200'],
            'mime_types.*' => ['string', 'max:191', 'regex:#^[a-z0-9][a-z0-9!\#$&^_.+-]*/[a-z0-9][a-z0-9!\#$&^_.+-]*$#i'],
            'on_threat' => ['sometimes', Rule::in(['reject', 'quarantine'])],

            // Text policies.
            'max_length' => ['sometimes', 'integer', 'min:1', 'max:10000000'],

            'checks' => ['sometimes', 'array'],
            'checks.*' => ['boolean'],

            'note' => ['nullable', 'string', 'max:500'],
        ];
    }

    public function withValidator(Validator $validator): void
    {
        $validator->after(function (Validator $validator): void {
            /** @var list<string> $forbidden */
            $forbidden = array_map(
                static fn (string $extension): string => mb_strtolower(ltrim($extension, '.')),
                (array) config('content-security.files.forbidden_extensions', []),
            );

            $requested = array_map(
                static fn (mixed $extension): string => mb_strtolower(ltrim((string) $extension, '.')),
                (array) $this->input('extensions', []),
            );

            $rejected = array_values(array_intersect($requested, $forbidden));

            if ($rejected !== []) {
                // The repository strips these anyway. Saying so out loud is
                // better than silently discarding what someone just typed.
                $validator->errors()->add(
                    'extensions',
                    sprintf(
                        'These extensions are server-executable and cannot be allowed from here: .%s. Change forbidden_extensions in config if you truly intend this.',
                        implode(', .', $rejected),
                    ),
                );
            }
        });
    }

    /**
     * Only the fields for this policy's type, so a text policy cannot be
     * handed a max_size and a file policy cannot be handed a max_length.
     *
     * @return array<string, mixed>
     */
    public function settings(): array
    {
        $keys = $this->string('type')->value() === 'file'
            ? ['label', 'max_size', 'extensions', 'mime_types', 'checks', 'on_threat']
            : ['label', 'max_length', 'checks'];

        return array_intersect_key($this->validated(), array_flip($keys));
    }
}
