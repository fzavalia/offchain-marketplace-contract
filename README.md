# Off-Chain Marketplace Contract

This repository contains a Marketplace Smart Contract that allows users to perform trades using EIP712 signatures. Users can sign trades indicating the terms of what will be traded, and other interested parties can accept and settle those trades on the blockchain.

## Trades

Trades are the main entity the Marketplace contract works with.

They consist of the assets that will be sent by the signer of the trade, the assets that the signer expects to receive, and various checks that provide extra validations (expiration, uses, signature indexes, etc.).

## Assets

Assets represent the items that will be swapped in a trade.

Assets in the "sent" property of the trade are those that the signer is willing to exchange, while assets in the "received" property are those that the signer wants to obtain after the trade.

They are composed of an asset type, which indicates the kind of asset it is (ERC20, ERC721, Decentraland Collection Items, etc.). This asset type allows implementations to handle the transfer of those assets as needed.

Assets contain the contract address of the asset, a value indicating amounts or token IDs, some arbitrary extra data used by implementations to handle custom information such as Decentraland Estate fingerprints, and the beneficiary, which is the address that will ultimately receive the asset.

## Checks

These are a series of validations that the trade must pass to be considered acceptable.

These checks include various criteria, such as the number of times a trade can be executed, the start and expiration times of the trade, and the addresses permitted to execute the trade. Additionally, there are external checks, such as requiring ownership of an NFT from a specific collection to accept the trade. The contract owner or individual signers can also use several indexes to cancel existing trades.

## Implementations

For Decentraland, the Marketplace Contract is implemented to support our assets, as well as our current fee and royalty system. There are two different implementations: one for the Ethereum network, which focuses on LANDs, Estates, and Names, and another for the Polygon network, which focuses on Collection items for primary (minting) and secondary (trading) sales.

The Ethereum Decentraland Marketplace allows for the trade of ERC721 tokens such as LANDs and Names, as well as composable ERC721 tokens like Estates. All ERC20 trades will incur a fee, which is sent to the fee collector, the Decentraland DAO.

The Polygon Decentraland Marketplace allows for the trade of ERC721 tokens such as Decentraland Collection NFTs and collection items, which are minted and sent to the interested user. It also includes logic to compute the fees to be paid as royalties and the fees owed to the DAO. Unlike the Ethereum Marketplace, it supports Meta Transactions.

## Coupons

This repository also contains contracts relevant to the concept of Coupons. Coupons are an extension of the Marketplace that allow users to create elements that can be applied to trades to modify them. A great example of this would be discount coupons.

Both the Decentraland Ethereum and Polygon Marketplaces support applying coupons to trades.

Currently, the only available coupon is the CollectionDiscountCoupon, which allows collection creators to offer discounts on their collection items being sold.

The Coupon entity comprises the same checks found in the trade, allowing it to be created with the same set of validations. It includes the contract address of the Coupon implementation, which must be authorized in the Coupon Manager contract to be usable in the Marketplace implementation. Additionally, it contains some arbitrary data, which is interpreted by the Coupon implementation contract, and extra data sent by the caller that is not validated in the signature. For example, in the case of the CollectionDiscountCoupon, this extra data can include the Merkle proof that verifies the collection item being bought qualifies for the discount.

## Signatures

This section contains examples on how to create and sign trades off-chain to be used later in a transaction.

**Signing Trades**

TODO: 

**Signing Coupons**

TODO: 

## Development

This repository was built using foundry.

To be able to do anything more than just look at it you will need to install foundry.

The instructions on how to do so can be found [here](https://book.getfoundry.sh/).

Once foundry has been installed,

- Build contracts with `forge build`
- Run tests with `forge test`

Make sure to read the framework docs to understand everything it offers.

## Deployment

Before deploying,

- Run `forge clean` to reset the workspace.
- Run `forge build` to prepare the contracts.
- Run `forge test` to make sure all tests pass.

Just running `forge test` should be enough, but I find it a good practice to run the other commands as well first to make sure.

It would be a good idea to check the foundry deployment [docs](https://book.getfoundry.sh/forge/deploying).

The contracts are to be deployed in the following order,

Ethereum: 

- DecentralandMarketplaceEthereum.sol
- CouponManager.sol (Optional as there are no Coupons for the Ethereum Marketplace right now)

Polygon:

- DecentralandMarketplacePolygon.sol
- CollectionDiscountCoupon.sol
- CouponManager.sol

The step by step of how to deploy them using foundry is,

Ethereum:

**DecentralandMarketplaceEthereum.sol**

```bash
$ forge create --rpc-url {rpcUrl} --constructor-args 0x9A6ebE7E2a7722F8200d0ffB63a1F6406A0d7dce 0x0000000000000000000000000000000000000000 0x9A6ebE7E2a7722F8200d0ffB63a1F6406A0d7dce 25000 0x0f5d2fb29fb7d3cfee444a200298f468908cc942 0x82A44D92D6c329826dc557c5E1Be6ebeC5D5FeB9 86400 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419 3600 --private-key {privateKey} src/marketplace/DecentralandMarketplaceEthereum.sol:DecentralandMarketplaceEthereum
```

Constructor Args:

- `0x9A6ebE7E2a7722F8200d0ffB63a1F6406A0d7dce` DAO as Owner
- `0x0000000000000000000000000000000000000000` No Coupon Manager
- `0x9A6ebE7E2a7722F8200d0ffB63a1F6406A0d7dce` DAO as Fee Collector
- `25000` Fee rate (2.5%)
- `0x0f5d2fb29fb7d3cfee444a200298f468908cc942` MANA
- `0x82A44D92D6c329826dc557c5E1Be6ebeC5D5FeB9` MANA / ETH Chainlink Aggregator
- `86400` MANA / ETH Aggregator Heartbeat (Used as tolerance)
- `0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419` ETH / USD Chainlink Aggregator
- `3600` ETH / USD Aggregator Heartbeat (Used as tolerance)

**CouponManager.sol**

```bash
$ forge create --rpc-url {rpcUrl} --constructor-args {decentralandMarketplaceEthereum} 0x9A6ebE7E2a7722F8200d0ffB63a1F6406A0d7dce \[\] --private-key {privateKey} src/coupons/CouponManager.sol:CouponManager
```

Constructor Args:

- `decentralandMarketplaceEthereum` The address of the already deployed Ethereum marketplace
- `0x9A6ebE7E2a7722F8200d0ffB63a1F6406A0d7dce` DAO as Owner
- `\[\]` There are no coupon implementations currently on Ethereum so this goes as an empty array

> After the CouponManager is deployed on Ethereum. Call the `updateCouponManager` on the DecentralandEthereumMarketplace contract as the owner to set the CouponManager.

Polygon:

**DecentralandMarketplacePolygon.sol**

```bash
$ forge create --rpc-url {rpcUrl} --constructor-args 0x0E659A116e161d8e502F9036bAbDA51334F2667E 0x0000000000000000000000000000000000000000 0xB08E3e7cc815213304d884C88cA476ebC50EaAB2 25000 0x90958D4531258ca11D18396d4174a007edBc2b42 25000 0xA1c57f48F0Deb89f569dFbE6E2B7f46D33606fD4 0xA1CbF3Fe43BC3501e3Fc4b573e822c70e76A7512 27 --private-key {privateKey} src/marketplace/DecentralandMarketplacePolygon.sol:DecentralandMarketplacePolygon
```

Constructor Args:

- `0x0E659A116e161d8e502F9036bAbDA51334F2667E` SAB as owner
- `0x0000000000000000000000000000000000000000` No Coupon Manager
- `0xB08E3e7cc815213304d884C88cA476ebC50EaAB2` DAO as Fee Collector
- `25000` Fee rate (2.5%)
- `0x90958D4531258ca11D18396d4174a007edBc2b42` Royalty Manager
- `25000` Royalty rate (2.5%)
- `0xA1c57f48F0Deb89f569dFbE6E2B7f46D33606fD4` MANA
- `0xA1CbF3Fe43BC3501e3Fc4b573e822c70e76A7512` MANA / USD Chainlink Aggregator
- `27` MANA / USD Aggregator Heartbeat (Used as tolerance)

**CollectionDiscountCoupon.sol**

```bash
$ forge create --rpc-url {rpcUrl} --private-key {privateKey} src/coupons/CollectionDiscountCoupon.sol:CollectionDiscountCoupon      
```

**CouponManager.sol**

```bash
$ forge create --rpc-url {rpcUrl} --constructor-args {decentralandMarketplacePolygon} 0x0E659A116e161d8e502F9036bAbDA51334F2667E \[{collectionDiscountCoupon}\] --private-key {privateKey} src/coupons/CouponManager.sol:CouponManager
```

Constructor Args:

- `decentralandMarketplacePolygon` The address of the already deployed Polygon marketplace
- `0x0E659A116e161d8e502F9036bAbDA51334F2667E` SAB as owner
- `\[{collectionDiscountCoupon}\]` The deployed CollectionDiscountCoupon as the only allowed discount

> After the CouponManager is deployed on Polygon. Call the `updateCouponManager` on the DecentralandPolygonMarketplace contract as the owner to set the CouponManager.

## Notes For Auditors

The contracts that will be deployed are:

- src/marketplace/DecentralandMarketplacePolygon.sol
- src/marketplace/DecentralandMarketplaceEthereum.sol
- src/coupons/CouponManager.sol
- src/coupons/CollectionDiscountCoupon.sol
