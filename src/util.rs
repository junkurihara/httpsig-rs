/// Check duplicate elements in a vector
pub(crate) fn has_unique_elements<T>(iter: T) -> bool
where
  T: IntoIterator,
  T::Item: Eq + std::hash::Hash,
{
  let mut uniq = rustc_hash::FxHashSet::default();
  iter.into_iter().all(move |x| uniq.insert(x))
}
