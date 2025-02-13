(function() {
    var type_impls = Object.fromEntries([["indexmap",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Bucket%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/hashbrown/raw/mod.rs.html#292\">Source</a><a href=\"#impl-Bucket%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"struct\" href=\"hashbrown/raw/inner/struct.Bucket.html\" title=\"struct hashbrown::raw::inner::Bucket\">Bucket</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><section id=\"method.as_ptr\" class=\"method\"><a class=\"src rightside\" href=\"src/hashbrown/raw/mod.rs.html#314\">Source</a><h4 class=\"code-header\">pub fn <a href=\"hashbrown/raw/inner/struct.Bucket.html#tymethod.as_ptr\" class=\"fn\">as_ptr</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.pointer.html\">*mut T</a></h4></section><section id=\"method.drop\" class=\"method\"><a class=\"src rightside\" href=\"src/hashbrown/raw/mod.rs.html#334\">Source</a><h4 class=\"code-header\">pub unsafe fn <a href=\"hashbrown/raw/inner/struct.Bucket.html#tymethod.drop\" class=\"fn\">drop</a>(&amp;self)</h4></section><section id=\"method.read\" class=\"method\"><a class=\"src rightside\" href=\"src/hashbrown/raw/mod.rs.html#338\">Source</a><h4 class=\"code-header\">pub unsafe fn <a href=\"hashbrown/raw/inner/struct.Bucket.html#tymethod.read\" class=\"fn\">read</a>(&amp;self) -&gt; T</h4></section><section id=\"method.write\" class=\"method\"><a class=\"src rightside\" href=\"src/hashbrown/raw/mod.rs.html#342\">Source</a><h4 class=\"code-header\">pub unsafe fn <a href=\"hashbrown/raw/inner/struct.Bucket.html#tymethod.write\" class=\"fn\">write</a>(&amp;self, val: T)</h4></section><section id=\"method.as_ref\" class=\"method\"><a class=\"src rightside\" href=\"src/hashbrown/raw/mod.rs.html#346\">Source</a><h4 class=\"code-header\">pub unsafe fn <a href=\"hashbrown/raw/inner/struct.Bucket.html#tymethod.as_ref\" class=\"fn\">as_ref</a>&lt;'a&gt;(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.reference.html\">&amp;'a T</a></h4></section><section id=\"method.as_mut\" class=\"method\"><a class=\"src rightside\" href=\"src/hashbrown/raw/mod.rs.html#350\">Source</a><h4 class=\"code-header\">pub unsafe fn <a href=\"hashbrown/raw/inner/struct.Bucket.html#tymethod.as_mut\" class=\"fn\">as_mut</a>&lt;'a&gt;(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.reference.html\">&amp;'a mut T</a></h4></section><section id=\"method.copy_from_nonoverlapping\" class=\"method\"><a class=\"src rightside\" href=\"src/hashbrown/raw/mod.rs.html#355\">Source</a><h4 class=\"code-header\">pub unsafe fn <a href=\"hashbrown/raw/inner/struct.Bucket.html#tymethod.copy_from_nonoverlapping\" class=\"fn\">copy_from_nonoverlapping</a>(&amp;self, other: &amp;<a class=\"struct\" href=\"hashbrown/raw/inner/struct.Bucket.html\" title=\"struct hashbrown::raw::inner::Bucket\">Bucket</a>&lt;T&gt;)</h4></section></div></details>",0,"indexmap::map::core::raw::RawBucket"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-Bucket%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/hashbrown/raw/mod.rs.html#285\">Source</a><a href=\"#impl-Clone-for-Bucket%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"hashbrown/raw/inner/struct.Bucket.html\" title=\"struct hashbrown::raw::inner::Bucket\">Bucket</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/hashbrown/raw/mod.rs.html#287\">Source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.84.1/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"hashbrown/raw/inner/struct.Bucket.html\" title=\"struct hashbrown::raw::inner::Bucket\">Bucket</a>&lt;T&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/1.84.1/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.84.1/src/core/clone.rs.html#174\">Source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.84.1/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: &amp;Self)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/1.84.1/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","indexmap::map::core::raw::RawBucket"],["<section id=\"impl-Send-for-Bucket%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/hashbrown/raw/mod.rs.html#283\">Source</a><a href=\"#impl-Send-for-Bucket%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"hashbrown/raw/inner/struct.Bucket.html\" title=\"struct hashbrown::raw::inner::Bucket\">Bucket</a>&lt;T&gt;</h3></section>","Send","indexmap::map::core::raw::RawBucket"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[5859]}