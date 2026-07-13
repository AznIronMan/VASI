import { NEXT_PUBLIC_WEBAPP_URL } from '@documenso/lib/constants/app';
import { i18n, type MessageDescriptor } from '@lingui/core';

export const appMetaTags = (title?: MessageDescriptor) => {
  const description =
    "VASI is Clark & Burke's verified, authorized document-signing infrastructure for staff and invited recipients.";

  return [
    {
      title: title ? `${i18n._(title)} - VASI` : 'VASI',
    },
    {
      name: 'description',
      content: description,
    },
    {
      name: 'keywords',
      content: 'VASI, Clark and Burke, CNB, verified signing, authorized signing, document signing',
    },
    {
      name: 'author',
      content: 'Clark & Burke LLC',
    },
    {
      name: 'robots',
      content: 'noindex, nofollow, noarchive',
    },
    {
      property: 'og:title',
      content: 'VASI - Verified Authorized Signing Infrastructure',
    },
    {
      property: 'og:description',
      content: description,
    },
    {
      property: 'og:image',
      content: `${NEXT_PUBLIC_WEBAPP_URL()}/static/vasi-logo.png`,
    },
    {
      property: 'og:type',
      content: 'website',
    },
    {
      name: 'twitter:card',
      content: 'summary_large_image',
    },
    {
      name: 'twitter:description',
      content: description,
    },
    {
      name: 'twitter:image',
      content: `${NEXT_PUBLIC_WEBAPP_URL()}/static/vasi-logo.png`,
    },
  ];
};
