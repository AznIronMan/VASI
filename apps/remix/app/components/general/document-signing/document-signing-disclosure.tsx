import { cn } from '@documenso/ui/lib/utils';

import { Trans } from '@lingui/react/macro';
import type { HTMLAttributes } from 'react';
import { Link } from 'react-router';

export type DocumentSigningDisclosureProps = HTMLAttributes<HTMLParagraphElement>;

export const DocumentSigningDisclosure = ({ className, ...props }: DocumentSigningDisclosureProps) => {
  return (
    <p className={cn('text-muted-foreground text-xs', className)} {...props}>
      <Trans>
        By proceeding, you intend for your electronic signature to be applied to this document and acknowledge that VASI
        will record this action as your consent to sign. The legal effect of an electronic signature depends on the
        document, the parties, and applicable law.
      </Trans>
      <span className="mt-2 block">
        <Trans>
          Read the full{' '}
          <Link className="text-documenso-700 underline" to="/articles/signature-disclosure" target="_blank">
            signature disclosure
          </Link>
          .
        </Trans>
      </span>
    </p>
  );
};
