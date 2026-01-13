import IntegrationHeader from './integration-header';
import NiceModal from '@ebay/nice-modal-react';
import React from 'react';
import {Form, Heading, Icon, Modal, TextField} from '@tryghost/admin-x-design-system';
import {useQuery} from '@tanstack/react-query';
import {useRouting} from '@tryghost/admin-x-framework/routing';

interface AzureADStatus {
    enabled: boolean;
    configured: boolean;
}

const AzureADModal = NiceModal.create(() => {
    const {updateRoute} = useRouting();

    // Fetch Azure AD SSO status from the API
    const {data: status, isLoading} = useQuery<AzureADStatus>({
        queryKey: ['azureAdStatus'],
        queryFn: async () => {
            const response = await fetch('/ghost/api/admin/auth/azure/status');
            if (!response.ok) {
                return {enabled: false, configured: false};
            }
            return response.json();
        }
    });

    const isEnabled = status?.enabled ?? false;
    const isConfigured = status?.configured ?? false;

    return (
        <Modal
            afterClose={() => {
                updateRoute('integrations');
            }}
            cancelLabel='Close'
            okLabel=''
            size='md'
            testId='azure-ad-modal'
            title=''
        >
            <IntegrationHeader
                detail='Single Sign-On with Microsoft Entra ID (Azure AD)'
                icon={
                    <div className="flex h-14 w-14 items-center justify-center rounded-lg bg-[#0078d4]">
                        <Icon className="text-white" name="user" size={32} />
                    </div>
                }
                title='Azure AD SSO'
            />
            <div className='mt-7'>
                {isLoading ? (
                    <p className="text-grey-600">Loading configuration status...</p>
                ) : (
                    <>
                        <div className="mb-6 rounded-lg border border-grey-200 p-4 dark:border-grey-800">
                            <div className="flex items-center justify-between">
                                <span className="font-medium">SSO Status</span>
                                {isEnabled && isConfigured ? (
                                    <span className="inline-flex items-center rounded-full bg-green-100 px-2.5 py-0.5 text-sm font-medium text-green-800 dark:bg-green-900 dark:text-green-200">
                                        Active
                                    </span>
                                ) : (
                                    <span className="inline-flex items-center rounded-full bg-grey-100 px-2.5 py-0.5 text-sm font-medium text-grey-800 dark:bg-grey-800 dark:text-grey-200">
                                        Not Configured
                                    </span>
                                )}
                            </div>
                        </div>

                        <Form marginBottom={false} title='Configuration' grouped>
                            <Heading level={6}>
                                Azure AD SSO is configured via Ghost&apos;s config file
                            </Heading>
                            <p className="mt-2 text-sm text-grey-600 dark:text-grey-400">
                                To enable Azure AD SSO, add the following to your Ghost configuration file:
                            </p>
                            <pre className="mt-4 overflow-x-auto rounded-lg bg-grey-100 p-4 text-xs dark:bg-grey-900">
{`{
  "adapters": {
    "sso": {
      "active": "AzureADSSOAdapter",
      "AzureADSSOAdapter": {
        "tenantId": "your-azure-tenant-id",
        "clientId": "your-app-client-id",
        "clientSecret": "your-client-secret",
        "staffGroupMapping": {
          "AL_Blog_Admin": "Administrator",
          "AL_Blog_Author": "Author"
        },
        "memberGroups": ["AL_Blog_User"],
        "memberGroupMapping": {
          "AL_Blog_User": "Azure SSO User"
        }
      }
    }
  }
}`}
                            </pre>
                        </Form>

                        {isEnabled && isConfigured && (
                            <div className="mt-6">
                                <Form marginBottom={false} title='Login' grouped>
                                    <p className="text-sm text-grey-600 dark:text-grey-400">
                                        Users can sign in via Azure AD at:
                                    </p>
                                    <TextField
                                        readonly
                                        title='SSO Login URL'
                                        value={`${window.location.origin}/ghost/api/admin/auth/azure/redirect`}
                                    />
                                </Form>
                            </div>
                        )}

                        <div className="mt-6">
                            <Form marginBottom={false} title='Azure Portal Setup' grouped>
                                <ol className="list-inside list-decimal space-y-2 text-sm text-grey-600 dark:text-grey-400">
                                    <li>Go to Azure Portal → Microsoft Entra ID → App registrations</li>
                                    <li>Create a new registration or use an existing app</li>
                                    <li>Add redirect URI: <code className="rounded bg-grey-100 px-1 dark:bg-grey-800">{window.location.origin}/ghost/api/admin/auth/azure/callback</code></li>
                                    <li>Add API permissions: <code className="rounded bg-grey-100 px-1 dark:bg-grey-800">User.Read</code>, <code className="rounded bg-grey-100 px-1 dark:bg-grey-800">GroupMember.Read.All</code></li>
                                    <li>Create Azure AD groups and add users to control access</li>
                                </ol>
                            </Form>
                        </div>
                    </>
                )}
            </div>
        </Modal>
    );
});

export default AzureADModal;
