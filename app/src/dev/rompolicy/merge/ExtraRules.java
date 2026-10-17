package dev.rompolicy.merge;
import java.util.*;
import java.util.regex.*;

/** Deliberately no shell interpretation and no m4 execution. Unparsed input is a hard failure. */
public final class ExtraRules {
    private final Cil.Index index;private final Set<String> names;private final List<Cil.N> out=new ArrayList<>();private int next=0;
    // Read-only view of the merger's existing index. Parsing must never register rules
    // there, or the subsequent merge would incorrectly consider them already present.
    public ExtraRules(Cil.Index i){index=i;names=new HashSet<>(i.symbols.keySet());}
    static List<String> tokens(String s){
        List<String> r=new ArrayList<>();Matcher m=Pattern.compile("\"(?:\\\\.|[^\"\\\\])*\"|[{}:;,]|[^\\s{}:;,]+").matcher(s);
        int end=0;while(m.find()){if(!s.substring(end,m.start()).trim().isEmpty())throw new IllegalArgumentException("Bad extra-rule token");r.add(m.group());end=m.end();}
        if(!s.substring(end).trim().isEmpty())throw new IllegalArgumentException("Bad extra-rule suffix");return r;
    }
    private static class Cursor {
        List<String> t;int i=0;Cursor(String s){t=tokens(s);}
        String take(){if(i>=t.size())throw new IllegalArgumentException("Incomplete extra rule");return t.get(i++);}
        String peek(){return i<t.size()?t.get(i):"";}
        List<String> group(){List<String> r=new ArrayList<>();String s=take();if(s.equals("{")){while(!peek().equals("}")){if(peek().isEmpty())throw new IllegalArgumentException("Unclosed set");String q=take();if(!q.equals(","))r.add(q);}take();}else r.add(s);if(r.isEmpty())throw new IllegalArgumentException("Empty rule set");return r;}
        void finish(){if(peek().equals(";"))take();if(i!=t.size())throw new IllegalArgumentException("Unparsed extra-rule suffix: "+t.subList(i,t.size()));}
    }
    private void add(String s){Cil.N n=Cil.node(s);out.add(n);if(Cil.DECL.contains(n.head()))names.add(n.s(1));}
    private String selector(List<String> s){
        if(s.size()==1&&!s.get(0).equals("*")&&!s.get(0).startsWith("~"))return s.get(0);
        String expr=s.size()==1&&s.get(0).equals("*")?"(all)":"("+String.join(" ",s)+")";
        for(String x:s)if(x.startsWith("~")||x.equals("-"))throw new IllegalArgumentException("Complement TE selectors require explicit CIL; not guessed");
        String name="rpm_extra_set_"+(next++);while(names.contains(name))name="rpm_extra_set_"+(next++);
        add("(typeattribute "+name+")");add("(typeattributeset "+name+" "+expr+")");return name;
    }
    public List<Cil.N> parse(String text,String format){
        if(text.contains("\u0000")||text.contains("`"))throw new IllegalArgumentException("NUL/m4 syntax not supported");
        text=text.replaceAll("(?m)#.*$","");
        boolean te=format.equals("te")||(format.equals("auto")&&text.contains(":"));
        // TE is semicolon-delimited; Magisk is line-delimited, optional final semicolon.
        List<String> statements=te?Arrays.asList(text.split(";")):Arrays.asList(text.split("\\r?\\n"));
        for(String raw:statements){String line=raw.trim();if(line.isEmpty())continue;Cursor c=new Cursor(line);String op=c.take();
            // Assertions from every extra source are excluded, including xperm assertions.
            // Do not require their source-only classes/types to exist in the target.
            if(Arrays.asList("neverallow","neverallowxperm","dontaudit","dontauditxperm").contains(op))continue;
            if(Arrays.asList("allow","auditallow","dontaudit","neverallow","allowxperm","auditallowxperm","dontauditxperm").contains(op)){
                String src=selector(c.group()),dst=selector(c.group());if(c.peek().equals(":"))c.take();List<String> cls=c.group();
                if(cls.equals(Collections.singletonList("*")))cls=new ArrayList<>(index.classes.keySet());
                if(cls.isEmpty())throw new IllegalArgumentException("No target classes");
                String operation=op.endsWith("xperm")?c.take():"";List<String> ps=c.group();c.finish();
                for(String cl:cls){
                    // Syntax parsing is separate from target compatibility screening.
                    // Unknown classes/permissions go through Cil.Merger just like ROM CIL.
                    if(!operation.isEmpty()){
                        if(!operation.equals("ioctl"))throw new IllegalArgumentException("Only ioctl xperm is supported");
                        List<String> ranges=new ArrayList<>();
                        for(String p:ps){if(p.equals("*"))ranges.add("(range 0x0000 0xffff)");else if(p.matches("0x[0-9a-fA-F]+-0x[0-9a-fA-F]+")){String[] a=p.split("-");ranges.add("(range "+a[0]+" "+a[1]+")");}else if(p.matches("0x[0-9a-fA-F]+"))ranges.add(p);else throw new IllegalArgumentException("Unsupported xperm range: "+p);}
                        add("("+op.replace("xperm","x")+" "+src+" "+dst+" (ioctl "+cl+" ("+String.join(" ",ranges)+")))");
                    }else{
                        List<String> perms=ps.equals(Collections.singletonList("*"))?(index.classes.containsKey(cl)?new ArrayList<>(index.perms(cl)):Collections.singletonList("all")):ps;
                        if(op.equals("neverallow"))continue; // User explicitly opted out of assertion-based pruning.
                        add("("+op+" "+src+" "+dst+" ("+cl+" ("+String.join(" ",perms)+")))");
                    }
                }
            }else if(op.equals("permissive")){
                for(String t:c.group())add("(typepermissive "+t+")");c.finish();
            }else if(op.equals("attribute")){String a=c.take();c.finish();add("(typeattribute "+a+")");
            }else if(op.equals("type")){
                String t=c.take();add("(type "+t+")");List<String> attrs=new ArrayList<>();
                while(!c.peek().isEmpty()&&!c.peek().equals(";")){if(c.peek().equals(",")){c.take();continue;}attrs.addAll(c.group());}
                if(attrs.isEmpty()&&!te)attrs.add("domain");for(String a:attrs)add("(typeattributeset "+a+" ("+t+"))");c.finish();
            }else if(op.equals("typeattribute")){
                List<String> types=c.group(),attrs=c.group();c.finish();for(String a:attrs)add("(typeattributeset "+a+" ("+String.join(" ",types)+"))");
            }else if(Arrays.asList("type_transition","type_change","type_member").contains(op)){
                String src=c.take(),dst=c.take();if(c.peek().equals(":"))c.take();String cls=c.take(),def=c.take();String object=c.peek().isEmpty()||c.peek().equals(";")?"":c.take();c.finish();
                add("("+op.replace("_","")+" "+src+" "+dst+" "+cls+" "+(object.isEmpty()?"":object+" ")+def+")");
            }else throw new IllegalArgumentException("Unsupported extra rule (no silent omission): "+op+". m4 macros/deny/enforce and full policy.conf are not accepted.");
        }return out;
    }
}
