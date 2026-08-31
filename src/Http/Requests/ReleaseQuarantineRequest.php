<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

final class ReleaseQuarantineRequest extends FormRequest
{
    public function authorize(): bool
    {
        // The route already ran the Authorize middleware; repeating the
        // check here would only invite the two to disagree.
        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'disk' => ['required', 'string', 'max:64'],
            'path' => ['required', 'string', 'max:1024', 'not_regex:/\.\./'],

            // Releasing a file that has not passed a fresh clean scan is
            // possible and must be asked for in so many words. It is
            // dispatched as an audited event either way.
            'override' => ['sometimes', 'boolean'],
            'reason' => ['required_if:override,true', 'nullable', 'string', 'max:500'],
        ];
    }

    /**
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'reason.required_if' => 'An override needs a reason for the audit log.',
            'path.not_regex' => 'The target path may not contain directory traversal sequences.',
        ];
    }
}
