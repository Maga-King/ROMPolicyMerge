package dev.rompolicy.merge;

import java.util.*;
import java.util.function.Function;
import java.util.function.Consumer;
import java.util.regex.*;

/** CIL AST: preserve strings and set expressions, never regex-rewrite policy bodies. */
public final class Cil {
    public static final class N {
        public final List<Object> a=new ArrayList<>(4);
        public String s(int i){return i<a.size() && a.get(i) instanceof String?(String)a.get(i):"";}
        public N n(int i){return (N)a.get(i);}
        public String head(){return s(0);}
        public String text(){StringBuilder b=new StringBuilder();appendTo(b);return b.toString();}
        private void appendTo(StringBuilder b){b.append('(');for(int i=0;i<a.size();i++){if(i>0)b.append(' ');Object o=a.get(i);if(o instanceof N)((N)o).appendTo(b);else b.append(o);}b.append(')');}
        public N map(Function<String,String> f){N n=null;for(int i=0;i<a.size();i++){Object old=a.get(i),mapped=old instanceof N?((N)old).map(f):f.apply((String)old);if(n==null&&!Objects.equals(old,mapped)){n=new N();n.a.addAll(a.subList(0,i));}if(n!=null)n.a.add(mapped);}return n==null?this:n;}
        public Set<String> atoms(){Set<String> r=new LinkedHashSet<>();for(Object o:a)if(o instanceof N)r.addAll(((N)o).atoms());else r.add((String)o);return r;}
    }
    public static List<N> parse(String text){
        List<N> roots=new ArrayList<>();parse(text,roots::add);return roots;
    }
    /** Emit complete statements immediately; pool only short atoms, bounded per input. */
    public static void parse(String text,Consumer<N> sink){
        Deque<N> stack=new ArrayDeque<>();Map<String,String> atoms=new HashMap<>();int i=0;
        while(i<text.length()){
            char c=text.charAt(i);
            if(Character.isWhitespace(c)||c=='\ufeff'){i++;continue;}
            if(c==';'){while(i<text.length()&&text.charAt(i)!='\n')i++;continue;}
            if(c=='('){N n=new N();if(!stack.isEmpty())stack.peek().a.add(n);stack.push(n);if(stack.size()>256)throw new IllegalArgumentException("CIL nesting > 256");i++;continue;}
            if(c==')'){if(stack.isEmpty())throw new IllegalArgumentException("Unexpected ) at "+i);N n=stack.pop();if(stack.isEmpty())sink.accept(n);i++;continue;}
            int start=i;
            if(c=='"'){i++;boolean end=false;while(i<text.length()){char q=text.charAt(i++);if(q=='\\'){if(i<text.length())i++;}else if(q=='"'){end=true;break;}}if(!end)throw new IllegalArgumentException("Unterminated CIL string");}
            else {while(i<text.length()&&!Character.isWhitespace(text.charAt(i))&&"();".indexOf(text.charAt(i))<0)i++;}
            if(stack.isEmpty())throw new IllegalArgumentException("Atom outside CIL statement at "+start);
            String atom=text.substring(start,i);
            if(atom.length()<=128){String old=atoms.get(atom);if(old!=null)atom=old;else if(atoms.size()<65536)atoms.put(atom,atom);}
            stack.peek().a.add(atom);
        }
        if(!stack.isEmpty())throw new IllegalArgumentException("Unbalanced CIL");
    }
    public static N node(String s){List<N> n=parse(s);if(n.size()!=1)throw new IllegalArgumentException("Expected one statement");return n.get(0);}
    static final Set<String> TYPE_DECL=new HashSet<>(Arrays.asList("type","typeattribute","typealias"));
    static final Set<String> OPS=new HashSet<>(Arrays.asList("and","or","xor","not","all","range"));
    static final Set<String> DECL=new HashSet<>(Arrays.asList("type","typeattribute","typealias","role","roleattribute","boolean","tunable","context","classpermission","classmap"));
    static final Pattern GENERATED=Pattern.compile("(?:base|attr|cil_gen)[_a-zA-Z]*[0-9]+");
    static final Pattern VERSIONED=Pattern.compile("(.+)_(?:[0-9]{6}|[0-9]{2}_[0-9]+)");
    public static final class Index {
        public final Map<String,String> symbols=new LinkedHashMap<>();
        public final Map<String,Set<String>> classes=new LinkedHashMap<>(),commons=new HashMap<>();
        public final Map<String,String> classCommon=new HashMap<>();
        public final Set<String> exact=new HashSet<>();
        public final Map<String,N> keys=new HashMap<>();
        public final Map<String,List<N>> attributes=new HashMap<>();
        public final Map<String,String> aliases=new HashMap<>();
        public final Set<String> types=new LinkedHashSet<>();
        public void add(N n){
            exact.add(n.text());String h=n.head();
            if(DECL.contains(h))symbols.putIfAbsent(n.s(1),h);
            if(h.equals("type"))types.add(n.s(1));
            if((h.equals("class")||h.equals("common"))&&n.a.size()==3&&n.a.get(2) instanceof N){(h.equals("class")?classes:commons).put(n.s(1),n.n(2).atoms());}
            if(h.equals("classcommon"))classCommon.put(n.s(1),n.s(2));
            if(h.equals("typeattributeset")&&n.a.size()==3)attributes.computeIfAbsent(n.s(1),k->new ArrayList<>()).add(n.a.get(2) instanceof N?n.n(2):node("("+n.s(2)+")"));
            if(h.equals("typealiasactual"))aliases.put(n.s(1),n.s(2));
            String k=key(n);if(k!=null)keys.putIfAbsent(k,n);
        }
        public Set<String> perms(String cl){Set<String> r=new LinkedHashSet<>(classes.getOrDefault(cl,Collections.emptySet()));r.addAll(commons.getOrDefault(classCommon.get(cl),Collections.emptySet()));return r;}
        public boolean hasType(String x){return TYPE_DECL.contains(symbols.get(x))||x.equals("self")||x.equals("notself")||x.equals("other");}
        public void release(){symbols.clear();classes.clear();commons.clear();classCommon.clear();exact.clear();keys.clear();attributes.clear();aliases.clear();types.clear();}
        public Set<String> resolve(String x){return resolve(x,new HashSet<>());}
        private Set<String> resolve(String x,Set<String> seen){
            if(types.contains(x))return new HashSet<>(Collections.singleton(x));
            if(!seen.add(x))return new HashSet<>();
            Set<String> out=new HashSet<>();
            if(aliases.containsKey(x))out.addAll(resolve(aliases.get(x),seen));
            for(N e:attributes.getOrDefault(x,Collections.emptyList()))out.addAll(eval(e,new HashSet<>(seen)));
            return out;
        }
        private Set<String> value(Object x,Set<String> seen){return x instanceof N?eval((N)x,seen):resolve((String)x,seen);}
        private Set<String> eval(N e,Set<String> seen){
            String op=e.head();if(op.equals("all"))return new HashSet<>(types);
            if(op.equals("not")){Set<String> out=new HashSet<>(types);for(int i=1;i<e.a.size();i++)out.removeAll(value(e.a.get(i),new HashSet<>(seen)));return out;}
            Set<String> out=new HashSet<>();boolean first=true;
            for(int i=OPS.contains(op)?1:0;i<e.a.size();i++){
                Set<String> v=value(e.a.get(i),new HashSet<>(seen));
                if(op.equals("and")&&!first)out.retainAll(v);
                else if(op.equals("xor")){Set<String> both=new HashSet<>(out);both.retainAll(v);out.addAll(v);out.removeAll(both);}
                else out.addAll(v);first=false;
            }return out;
        }
    }
    public static String key(N n){
        String h=n.head();
        if(Arrays.asList("typetransition","typechange","typemember").contains(h)){
            if(n.a.size()!=5&&n.a.size()!=6)return null;
            return h+"|"+n.s(1)+"|"+n.s(2)+"|"+n.s(3)+"|"+(n.a.size()==6?n.s(4):"");
        }
        if(h.equals("genfscon")&&n.a.size()>=4){String k="genfscon|"+n.s(1)+"|"+n.s(2);if(n.a.size()==5)k+="|"+n.s(3);return k;}
        if(h.equals("typealiasactual"))return h+"|"+n.s(1);
        return null;
    }
    public static final class Entry {
        public final String path,origin;public final N node;public boolean active=true;
        public Entry(String p,String o,N n){path=p;origin=o;node=n;}
    }
    public interface Audit {void note(String status,String origin,N rule,String reason);}
    public static final class Merger {
        public final Index index;public final List<Entry> additions=new ArrayList<>();private final Audit audit;
        private final Set<String> baseTypes;private int serial=0;
        public boolean permissive=false,hardwareLabels=false;public String targetVersion="";
        public Merger(Index i,Audit a){index=i;audit=a;baseTypes=new HashSet<>(i.types);}
        public void merge(List<Entry> input,String namespace){
            Map<String,String> rename=new HashMap<>();
            for(Entry e:input)if(e.node.head().equals("typeattribute")&&GENERATED.matcher(e.node.s(1)).matches())rename.put(e.node.s(1),"rpm_"+namespace+"_"+e.node.s(1));
            List<Entry> transformed=new ArrayList<>();
            Map<String,String> mappedAtoms=new HashMap<>();
            Function<String,String> adapt=s->{
                if(s.startsWith("\""))return s;
                if(rename.containsKey(s))return rename.get(s);
                Matcher version=VERSIONED.matcher(s);
                if(!index.hasType(s)&&version.matches()){
                    String plain=version.group(1);
                    if(!targetVersion.isEmpty()&&index.hasType(plain+"_"+targetVersion))return plain+"_"+targetVersion;
                    if(index.hasType(plain))return plain;
                }return s;
            };
            for(Entry e:input){N n=e.node.map(s->{String mapped=mappedAtoms.get(s);if(mapped!=null)return mapped;mapped=adapt.apply(s);if(mappedAtoms.size()<65536)mappedAtoms.put(s,mapped);return mapped;});transformed.add(n==e.node?e:new Entry(e.path,e.origin,n));}
            // Declarations first; rule order must not discard forward references.
            for(Entry e:transformed)if(DECL.contains(e.node.head())){
                N n=e.node;String old=index.symbols.get(n.s(1));
                if(old==null)accept(e);
                else if(!old.equals(n.head()))skip(e,"declaration-kind conflict; target retained");
                else if(!index.exact.contains(n.text())&&!Arrays.asList("type","typeattribute","role","roleattribute","typealias").contains(n.head()))skip(e,"different named declaration; target retained");
            }
            for(Entry e:transformed)if(!DECL.contains(e.node.head()))mergeRule(e);
        }
        private void accept(Entry e){if(index.exact.contains(e.node.text()))return;index.add(e.node);additions.add(e);audit.note("ADDED",e.origin,e.node,e.path);}
        private void skip(Entry e,String reason){audit.note("SKIPPED",e.origin,e.node,reason);}
        private boolean checkTypes(Entry e,Collection<String> refs){for(String s:refs)if(!OPS.contains(s)&&!index.hasType(s)){skip(e,"unresolved type/attribute: "+s);return false;}return true;}
        private void mergeRule(Entry e){
            N n=e.node;String h=n.head();if(index.exact.contains(n.text()))return;
            if(h.equals("neverallow")||h.equals("neverallowx")){audit.note("EXCLUDED",e.origin,n,"source assertion not imported; target assertions retained; compiler -N");return;}
            if(h.equals("dontaudit")||h.equals("dontauditx")){audit.note("EXCLUDED",e.origin,n,"source dontaudit excluded at user request; target original rules unchanged");return;}
            if(h.equals("typepermissive")){
                if(!permissive||Arrays.asList("init","vendor_init","ueventd").contains(n.s(1))){skip(e,"permissive import disabled/protected early-init domain");return;}
                if(checkTypes(e,Arrays.asList(n.s(1))))accept(e);return;
            }
            if(h.equals("typeattributeset")){
                if(n.a.size()!=3){skip(e,"unsupported attribute expression");return;}
                if(!(n.a.get(2) instanceof N)){n=node("(typeattributeset "+n.s(1)+" ("+n.s(2)+"))");e=new Entry(e.path,e.origin,n);}
                if(!"typeattribute".equals(index.symbols.get(n.s(1)))){skip(e,"source version alias resolved to concrete target type; do not redefine target as attribute");return;}
                Set<String> refs=n.n(2).atoms();refs.add(n.s(1));if(!checkTypes(e,refs))return;
                // Partition ownership of existing property types must not be reassigned through a versioned alias.
                if(n.s(1).matches("(?:system|vendor|product)_(?:(?:internal|restricted|public)_)?property_type")){
                    Set<String> resolved=new HashSet<>();N expr=n.n(2);
                    if(!Collections.disjoint(expr.atoms(),OPS)){skip(e,"complex property ownership assignment needs manual review");return;}
                    for(String s:expr.atoms())resolved.addAll(index.resolve(s));
                    resolved.removeAll(baseTypes);
                    if(resolved.isEmpty()){skip(e,"preserve existing target property ownership");return;}
                    N safe=node("(typeattributeset "+n.s(1)+" ("+String.join(" ",resolved)+"))");accept(new Entry(e.path,e.origin,safe));return;
                }
                accept(e);return;
            }
            if(Arrays.asList("allow","auditallow","dontaudit","allowx","auditallowx","dontauditx").contains(h)){
                if(n.a.size()!=4||!(n.a.get(3) instanceof N)){skip(e,"unsupported access rule shape");return;}
                if(!checkTypes(e,Arrays.asList(n.s(1),n.s(2))))return;
                N cp=n.n(3);
                if(h.endsWith("x")){
                        if(cp.a.size()!=3||!cp.s(0).equals("ioctl")||!index.classes.containsKey(cp.s(1))){skip(e,"目标不支持该扩展权限对象类或操作");return;}
                        if(!index.perms(cp.s(1)).contains("ioctl")){skip(e,"目标对象类 "+cp.s(1)+" 没有 ioctl 权限，不能加入此 ioctl 扩展规则");return;}accept(e);return;
                }
                if(cp.a.size()!=2||!(cp.a.get(1) instanceof N)||!index.classes.containsKey(cp.s(0))){skip(e,"unavailable class or named classpermission expression");return;}
                Set<String> perms=cp.n(1).atoms();perms.removeAll(OPS);
                Set<String> absent=new HashSet<>(perms);absent.removeAll(index.perms(cp.s(0)));
                if(!absent.isEmpty()){
                    if(!Collections.disjoint(cp.n(1).atoms(),OPS)){skip(e,"missing permissions in complex expression: "+absent);return;}
                    perms.removeAll(absent);audit.note("FILTERED",e.origin,n,"目标对象类 "+cp.s(0)+" 不存在权限 "+absent+"；仅排除这些无效权限，其余保留");
                    if(perms.isEmpty())return;
                    n=node("("+h+" "+n.s(1)+" "+n.s(2)+" ("+cp.s(0)+" ("+String.join(" ",perms)+")))");e=new Entry(e.path,e.origin,n);
                }accept(e);return;
            }
            if(Arrays.asList("typetransition","typechange","typemember").contains(h)){
                if(n.a.size()!=5&&n.a.size()!=6){skip(e,"invalid transition shape");return;}
                if(!checkTypes(e,Arrays.asList(n.s(1),n.s(2),n.s(n.a.size()-1))))return;
                if(!index.classes.containsKey(n.s(3))){skip(e,"missing transition class");return;}
            }else if(h.equals("roletype")){
                if(!index.symbols.containsKey(n.s(1))||!checkTypes(e,Arrays.asList(n.s(2)))){skip(e,"missing role/type");return;}
            }else if(h.equals("typealiasactual")){
                if(!checkTypes(e,Arrays.asList(n.s(1),n.s(2))))return;
            }else if(h.equals("expandtypeattribute")){
                if(!(n.a.get(1) instanceof N)||!checkTypes(e,n.n(1).atoms()))return;
                List<String> attrs=new ArrayList<>();for(String s:n.n(1).atoms())if("typeattribute".equals(index.symbols.get(s)))attrs.add(s);
                if(attrs.isEmpty()){skip(e,"version alias expansion resolved to concrete type; expansion hint is inapplicable");return;}
                if(attrs.size()!=n.n(1).a.size()){n=node("(expandtypeattribute ("+String.join(" ",attrs)+") "+n.s(2)+")");e=new Entry(e.path,e.origin,n);}
            }else if(h.equals("genfscon")){
                if(!hardwareLabels){skip(e,"hardware genfs labels disabled; optional hardware-label checkbox");return;}
            }else {skip(e,"structural/nested form not automatically merged: "+h);return;}
            String key=key(n);
            if(key!=null&&index.keys.containsKey(key)){
                if(!index.keys.get(key).text().equals(n.text())){
                    if(h.equals("genfscon"))audit.note("CONTEXT_CONFLICT",e.origin,n,"genfscon same-key conflict; retained: "+index.keys.get(key).text());
                    else skip(e,"same-key conflict; target/earlier rule retained");
                }return;
            }
            accept(e);
        }
        /** Only compiler-proven transition conflicts are removed, never broad allow rules. */
        public boolean resolveTransitionConflict(String log){
            if(!log.contains("Conflicting type rules"))return false;
            Matcher m=Pattern.compile("Expanded from type rule \\(scontext=(\\S+) tcontext=(\\S+) tclass=(\\S+) result=([^\\s)]+)\\)").matcher(log);
            while(m.find())for(Entry e:additions)if(e.active&&Arrays.asList("typetransition","typechange","typemember").contains(e.node.head())){
                N n=e.node;if(n.s(1).equals(m.group(1))&&n.s(2).equals(m.group(2))&&n.s(3).equals(m.group(3))&&n.s(n.a.size()-1).equals(m.group(4))){e.active=false;audit.note("COMPILER_CONFLICT",e.origin,n,"added transition rejected by full compile; existing policy unchanged");return true;}
            }return false;
        }
    }
}
