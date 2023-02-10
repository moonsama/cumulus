use sp_runtime::DigestItem;

pub trait DigestsProvider<Id, BlockHash> {
	type Digests: IntoIterator<Item = DigestItem>;
	fn provide_digests(&self, id: Id, parent: BlockHash) -> Self::Digests;
}

impl<Id, BlockHash> DigestsProvider<Id, BlockHash> for () {
	type Digests = [DigestItem; 0];
	fn provide_digests(&self, _id: Id, _parent: BlockHash) -> Self::Digests {
		[]
	}
}

impl<F, Id, BlockHash, D> DigestsProvider<Id, BlockHash> for F
where
	F: Fn(Id, BlockHash) -> D,
	D: IntoIterator<Item = DigestItem>,
{
	type Digests = D;

	fn provide_digests(&self, id: Id, parent: BlockHash) -> Self::Digests {
		(*self)(id, parent)
	}
}
