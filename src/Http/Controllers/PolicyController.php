<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Inertia\Response as InertiaResponse;
use LaravelPlus\ContentSecurity\Contracts\PolicyRepository;
use LaravelPlus\ContentSecurity\Domain\Policy\SecurityPolicy;
use LaravelPlus\ContentSecurity\Http\Controllers\Concerns\RendersConsole;
use LaravelPlus\ContentSecurity\Http\Requests\UpdatePolicyRequest;
use LaravelPlus\ContentSecurity\Http\Resources\PolicyResource;

/**
 * Policies are config first. The database, when runtime editing is enabled,
 * holds overrides on top of that baseline — and the console shows which is
 * which, so nobody has to guess whether a limit came from the repository or
 * from someone's afternoon.
 */
final class PolicyController extends Controller
{
    use RendersConsole;

    public function index(Request $request, PolicyRepository $policies): InertiaResponse|JsonResponse
    {
        return $this->render($request, 'Policies/Index', [
            'filePolicies' => $this->describe($policies, $policies->allFile(), 'file'),
            'textPolicies' => $this->describe($policies, $policies->allText(), 'text'),
            'defaults' => [
                'file' => (string) config('content-security.files.default_policy', 'default'),
                'text' => (string) config('content-security.text.default_policy', 'default'),
            ],
            'global' => [
                'enabled' => (bool) config('content-security.enabled', true),
                'failClosed' => (bool) config('content-security.fail_closed', true),
                'malwareDriver' => (string) config('content-security.malware.default', 'null'),
                'quarantineDisk' => (string) config('content-security.storage.quarantine_disk', 'local'),
            ],
            'limits' => [
                'maxSizeCeiling' => (int) config('content-security.files.max_size_ceiling', 512 * 1024 * 1024),
                'forbiddenExtensions' => array_values((array) config('content-security.files.forbidden_extensions', [])),
            ],
            'archives' => (array) config('content-security.archives', []),
            'images' => (array) config('content-security.images', []),
            'pdf' => (array) config('content-security.pdf', []),
            'html' => [
                'allowedTags' => (array) config('content-security.html.allowed_tags', []),
                'allowedSchemes' => (array) config('content-security.html.allowed_schemes', []),
                'allowInlineStyles' => (bool) config('content-security.html.allow_inline_styles', false),
                'allowedIframeHosts' => (array) config('content-security.html.allowed_iframe_hosts', []),
            ],
            'editable' => $this->editable(),
        ]);
    }

    public function update(
        UpdatePolicyRequest $request,
        string $policy,
        PolicyRepository $policies,
    ): RedirectResponse {
        abort_unless($this->editable(), 403, 'Runtime policy editing is disabled.');

        $policies->override(
            type: $request->string('type')->value(),
            name: $policy,
            settings: $request->settings(),
            actorId: $request->user()?->getAuthIdentifier(),
            note: $request->string('note')->value() ?: null,
        );

        return back()->with('success', sprintf('Policy [%s] updated. The change is recorded in the audit log.', $policy));
    }

    public function reset(
        Request $request,
        string $policy,
        PolicyRepository $policies,
    ): RedirectResponse {
        abort_unless($this->editable(), 403, 'Runtime policy editing is disabled.');

        $type = $request->string('type')->value() === 'text' ? 'text' : 'file';
        $policies->reset($type, $policy);

        return back()->with('success', sprintf('Policy [%s] reset to its config baseline.', $policy));
    }

    private function editable(): bool
    {
        return (bool) config('content-security.admin.manage_policies', true)
            && (bool) config('content-security.persistence.enabled', true);
    }

    /**
     * @param  list<SecurityPolicy>  $list
     * @return list<array<string, mixed>>
     */
    private function describe(PolicyRepository $policies, array $list, string $type): array
    {
        return array_values(array_map(
            static fn (SecurityPolicy $policy): array => [
                ...(new PolicyResource($policy))->resolve(),
                // Shown in the console so an operator can tell a reviewed
                // default from a runtime edit at a glance.
                'source' => $policies->isOverridden($type, $policy->name()) ? 'database' : 'config',
            ],
            $list,
        ));
    }
}
