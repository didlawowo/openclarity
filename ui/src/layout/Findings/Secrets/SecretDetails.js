import React from 'react';
import { useLocation } from 'react-router-dom';
import TabbedPage from 'components/TabbedPage';
import { AssetDetails, ScanDetails } from 'layout/detail-displays';
import FindingsDetailsPage from '../FindingsDetailsPage';
import TabSecretDetails from './TabSecretDetails';

const SECRET_DETAILS_PATHS = {
    SECRET_DETAILS: "",
    ASSET_DETAILS: "asset",
    SCAN_DETAILS: "scan"
}

const DetailsContent = ({data}) => {
    const {pathname} = useLocation();
    
    const {id, scan, asset} = data;
    
    return (
        <TabbedPage
            basePath={`${pathname.substring(0, pathname.indexOf(id))}${id}`}
            items={[
                {
                    id: "general",
                    title: "Secret details",
                    isIndex: true,
                    component: () => <TabSecretDetails data={data} />
                },
                {
                    id: "asset",
                    title: "Asset details",
                    path: SECRET_DETAILS_PATHS.ASSET_DETAILS,
                    component: () => <AssetDetails assetData={asset} withAssetLink />
                },
                {
                    id: "scan",
                    title: "Scan details",
                    path: SECRET_DETAILS_PATHS.SCAN_DETAILS,
                    component: () => <ScanDetails scanData={scan} withScanLink />
                }
            ]}
            withInnerPadding={false}
        />
    )
}

const SecretDetails = () => (
    <FindingsDetailsPage
        backTitle="Secrets"
        getTitleData={({findingInfo}) => ({title: findingInfo.fingerprint})}
        detailsContent={DetailsContent}
    />
)

export default SecretDetails;